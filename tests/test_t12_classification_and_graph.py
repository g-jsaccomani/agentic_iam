"""T12 — Principal Classification, Permission-Derived Secret/KMS Access, Folder Scoping & Graph Accuracy."""

from __future__ import annotations

import re

from backend.tools import (
    asset_key_secret_inventory as inv_mod,
    cai_collector as cai_mod,
    graph_engine as graph_mod,
    onboarding_manager as onb_mod,
    posture_scoring_engine as score_mod,
)


def test_default_appengine_and_cloudbuild_sas_appear_in_bindings_and_impact_wkl03(
    fake_session,
    fake_gcp,
) -> None:
    scope = "organizations/123456789012"
    appengine_sa = "proj-alpha@appspot.gserviceaccount.com"
    cloudbuild_sa = "100200300@cloudbuild.gserviceaccount.com"

    assert cai_mod.is_google_managed_service_agent(f"serviceAccount:{appengine_sa}") is False
    assert cai_mod.is_google_managed_service_agent(f"serviceAccount:{cloudbuild_sa}") is False
    assert cai_mod.is_default_service_account_email(appengine_sa) is True
    assert cai_mod.is_default_service_account_email(cloudbuild_sa) is True

    fake_gcp.add(
        "GET",
        re.compile(r":searchAllResources"),
        handler=lambda m, u, params=None, json_body=None: (
            200,
            {
                "results": [
                    {
                        "name": "//cloudresourcemanager.googleapis.com/projects/proj-alpha",
                        "project": "projects/100200300",
                        "state": "ACTIVE",
                        "assetType": "cloudresourcemanager.googleapis.com/Project",
                    }
                ]
                if "Project" in str((params or {}).get("assetTypes", ""))
                else [
                    {
                        "name": f"//iam.googleapis.com/projects/proj-alpha/serviceAccounts/{appengine_sa}",
                        "assetType": "iam.googleapis.com/ServiceAccount",
                        "project": "projects/100200300",
                        "project_id": "proj-alpha",
                        "additionalAttributes": {"email": appengine_sa},
                    }
                ]
            },
        ),
    )
    fake_gcp.add(
        "GET",
        re.compile(r":searchAllIamPolicies"),
        data={
            "results": [
                {
                    "resource": "//cloudresourcemanager.googleapis.com/projects/proj-alpha",
                    "project": "projects/100200300",
                    "assetType": "cloudresourcemanager.googleapis.com/Project",
                    "policy": {
                        "bindings": [
                            {
                                "role": "roles/editor",
                                "members": [f"serviceAccount:{appengine_sa}"],
                            }
                        ]
                    },
                }
            ]
        },
    )
    fake_gcp.add("POST", re.compile(r":getIamPolicy"), data={"bindings": []})
    fake_gcp.add("POST", re.compile(r":getEffectiveOrgPolicy"), status=404, data={})
    fake_gcp.add("GET", re.compile(r"/keys"), data={"keys": []})
    fake_gcp.add("GET", re.compile(r"iam\.googleapis\.com/v1/roles/"), status=404, data={})
    fake_gcp.add("POST", re.compile(r"entries:list"), data={"entries": []})

    bindings = cai_mod.collect_live_iam_bindings(scope, force_refresh=True)
    app_bindings = [b for b in bindings if b["principal"] == f"serviceAccount:{appengine_sa}"]
    assert len(app_bindings) == 1
    assert app_bindings[0]["is_google_service_agent"] is False
    assert app_bindings[0]["is_default_sa"] is True

    det = score_mod.compute_iam_framework_baseline(scope, force_refresh=True)
    wkl03 = [c for c in det["control_evaluations"] if c["control_id"] == "IAM-WKL-03"][0]
    assert wkl03["deterministic_score_pct"] < 100.0
    assert "1 of 1 Default SAs hold active IAM role bindings" in wkl03["evidence_summary"]


def test_sa_from_external_project_is_marked_external_and_incomplete_list_is_unknown(
    fake_session,
    fake_gcp,
) -> None:
    scope = "organizations/123456789012"
    internal_sa = "serviceAccount:app@proj-in-org.iam.gserviceaccount.com"
    external_sa = "serviceAccount:vendor@foreign-org-proj.iam.gserviceaccount.com"

    fake_gcp.add(
        "GET",
        re.compile(r":searchAllResources"),
        data={
            "results": [
                {
                    "name": "//cloudresourcemanager.googleapis.com/projects/proj-in-org",
                    "project": "projects/111111",
                    "state": "ACTIVE",
                }
            ]
        },
    )
    fake_gcp.add(
        "GET",
        re.compile(r":searchAllIamPolicies"),
        data={
            "results": [
                {
                    "resource": "//cloudresourcemanager.googleapis.com/projects/proj-in-org",
                    "project": "projects/111111",
                    "policy": {
                        "bindings": [
                            {"role": "roles/viewer", "members": [internal_sa, external_sa]}
                        ]
                    },
                }
            ]
        },
    )
    fake_gcp.add("POST", re.compile(r":getIamPolicy"), data={"bindings": []})

    bindings = cai_mod.collect_live_iam_bindings(scope, force_refresh=True)
    by_pr = {b["principal"]: b for b in bindings}
    assert by_pr[internal_sa]["is_external"] is False
    assert by_pr[internal_sa]["external_classification"] == "internal"
    assert by_pr[external_sa]["is_external"] is True
    assert by_pr[external_sa]["external_classification"] == "external"

    # Incomplete project list -> never silently internal; marked unknown
    unk = cai_mod.classify_principal_domain_and_type(
        external_sa,
        org_project_identifiers={"proj-in-org"},
        org_projects_complete=False,
    )
    assert unk["external_classification"] == "unknown"


def test_deleted_principal_and_missing_org_domains_classification(fake_session, monkeypatch) -> None:
    deleted = cai_mod.classify_principal_domain_and_type("deleted:user:old@example.com?uid=998877")
    assert deleted["principal_type"] == "deleted"
    assert deleted["is_external"] is False
    assert deleted["external_classification"] == "deleted"

    # Multi-domain organization_domains set on session
    fake_session.organization_domain = "corp.example"
    fake_session.organization_domains = {"corp.example", "subsidiary.example"}
    sub_user = cai_mod.classify_principal_domain_and_type("user:ana@subsidiary.example")
    assert sub_user["is_external"] is False
    assert sub_user["external_classification"] == "internal"

    # Missing org domains -> unknown + coverage warning (never silently internal)
    fake_session.organization_domain = ""
    fake_session.organization_domains = set()
    monkeypatch.setattr(cai_mod.settings, "organization_domain", "")
    cov_scope = "organizations/123456789012"
    res = cai_mod.classify_principal_domain_and_type("user:bob@unknowncorp.io", coverage_scope=cov_scope)
    assert res["external_classification"] == "unknown"
    cov = cai_mod.summarize_scan_coverage(cov_scope)
    assert any("organization_domains" in w for w in cov["coverage_warnings"])


def test_roles_editor_is_not_secret_reader_and_folder_bindings_are_ancestry_scoped(
    fake_session,
    fake_gcp,
) -> None:
    scope = "organizations/123456789012"

    def _resources_handler(method, url, params=None, json_body=None):
        atypes = str((params or {}).get("assetTypes", ""))
        if "cloudresourcemanager.googleapis.com/Project" in atypes:
            return (
                200,
                {
                    "results": [
                        {
                            "name": "//cloudresourcemanager.googleapis.com/projects/proj-a",
                            "project": "projects/101",
                            "state": "ACTIVE",
                            "folders": ["folders/111"],
                        },
                        {
                            "name": "//cloudresourcemanager.googleapis.com/projects/proj-b",
                            "project": "projects/202",
                            "state": "ACTIVE",
                            "folders": ["folders/222"],
                        },
                    ]
                },
            )
        return (
            200,
            {
                "results": [
                    {
                        "name": "//secretmanager.googleapis.com/projects/proj-a/secrets/sec-a",
                        "assetType": "secretmanager.googleapis.com/Secret",
                        "project": "projects/101",
                        "folders": ["folders/111"],
                        "versionedResources": [{"resource": {"replication": {"automatic": {}}}}],
                    },
                    {
                        "name": "//secretmanager.googleapis.com/projects/proj-b/secrets/sec-b",
                        "assetType": "secretmanager.googleapis.com/Secret",
                        "project": "projects/202",
                        "folders": ["folders/222"],
                        "versionedResources": [{"resource": {"replication": {"automatic": {}}}}],
                    },
                    {
                        "name": "//iam.googleapis.com/projects/proj-a/roles/customSecretReader",
                        "assetType": "iam.googleapis.com/Role",
                        "project": "projects/101",
                        "versionedResources": [
                            {
                                "resource": {
                                    "name": "projects/proj-a/roles/customSecretReader",
                                    "title": "Custom Secret Reader",
                                    "includedPermissions": ["secretmanager.versions.access"],
                                }
                            }
                        ],
                    },
                ]
            },
        )

    fake_gcp.add("GET", re.compile(r":searchAllResources"), handler=_resources_handler)
    fake_gcp.add(
        "GET",
        re.compile(r":searchAllIamPolicies"),
        data={
            "results": [
                {
                    "resource": "//cloudresourcemanager.googleapis.com/projects/proj-a",
                    "project": "projects/101",
                    "policy": {
                        "bindings": [
                            {"role": "roles/editor", "members": ["user:editor-only@example.com"]},
                            {
                                "role": "projects/proj-a/roles/customSecretReader",
                                "members": ["user:custom-reader@example.com"],
                            },
                        ]
                    },
                },
                {
                    "resource": "//cloudresourcemanager.googleapis.com/folders/111",
                    "policy": {
                        "bindings": [
                            {
                                "role": "roles/secretmanager.secretAccessor",
                                "members": ["user:folder111-reader@example.com"],
                            }
                        ]
                    },
                },
            ]
        },
    )
    fake_gcp.add("POST", re.compile(r":getIamPolicy"), data={"bindings": []})
    fake_gcp.add("POST", re.compile(r":getEffectiveOrgPolicy"), status=404, data={})
    fake_gcp.add("POST", re.compile(r"entries:list"), data={"entries": []})
    fake_gcp.add(
        "GET",
        "https://iam.googleapis.com/v1/roles/editor",
        data={
            "name": "roles/editor",
            "title": "Editor",
            "includedPermissions": ["compute.instances.list", "storage.objects.get"],
        },
    )
    fake_gcp.add(
        "GET",
        "https://iam.googleapis.com/v1/roles/secretmanager.secretAccessor",
        data={
            "name": "roles/secretmanager.secretAccessor",
            "title": "Secret Manager Secret Accessor",
            "includedPermissions": ["secretmanager.versions.access"],
        },
    )

    inv = inv_mod.build_accounts_keys_secrets_inventory(scope, force_refresh=True)
    by_acc = {a.principal: a for a in inv.accounts}
    assert by_acc["user:editor-only@example.com"].can_access_secrets is False
    assert by_acc["user:custom-reader@example.com"].can_access_secrets is True

    by_sec = {s.secret_name: s for s in inv.secrets}
    assert "user:editor-only@example.com" not in by_sec["sec-a"].accessor_principals
    assert "user:custom-reader@example.com" in by_sec["sec-a"].accessor_principals
    # Folder 111 binding applies to sec-a (in folders/111), NOT to sec-b (in folders/222)!
    assert "user:folder111-reader@example.com" in by_sec["sec-a"].accessor_principals
    assert "user:folder111-reader@example.com" not in by_sec["sec-b"].accessor_principals


def test_sa_key_without_keytype_is_unknown_high_risk(fake_session, fake_gcp) -> None:
    scope = "organizations/123456789012"
    sa_email = "worker@proj-a.iam.gserviceaccount.com"
    fake_gcp.add("GET", re.compile(r"/keys"), data={"keys": []})
    res = cai_mod.collect_unified_service_account_keys(
        scope,
        bindings=[],
        resources=[
            {
                "name": f"//iam.googleapis.com/projects/proj-a/serviceAccounts/{sa_email}/keys/abcd1234",
                "asset_type": "iam.googleapis.com/ServiceAccountKey",
                "project_id": "proj-a",
                "versioned_resource": {},  # Missing keyType!
                "additional_attributes": {},
            }
        ],
        force_refresh=True,
    )
    assert len(res["all_keys"]) == 1
    assert res["all_keys"][0]["key_type"] == "UNKNOWN"
    assert res["all_keys"][0]["risk_level"] == "HIGH"


def test_graph_token_creator_in_proj_b_does_not_reach_sa_owned_by_proj_a_and_vm_versioned_resource_creates_edge(
    fake_session,
    fake_gcp,
) -> None:
    scope = "organizations/123456789012"
    sa_a = "sa-a@proj-a.iam.gserviceaccount.com"
    vm_sa = "vm-runner@proj-a.iam.gserviceaccount.com"

    def _resources_handler(method, url, params=None, json_body=None):
        atypes = str((params or {}).get("assetTypes", ""))
        if "cloudresourcemanager.googleapis.com/Project" in atypes:
            return (
                200,
                {
                    "results": [
                        {"name": "//cloudresourcemanager.googleapis.com/projects/proj-a", "project": "projects/101", "state": "ACTIVE"},
                        {"name": "//cloudresourcemanager.googleapis.com/projects/proj-b", "project": "projects/202", "state": "ACTIVE"},
                    ]
                },
            )
        return (
            200,
            {
                "results": [
                    {
                        "name": f"//iam.googleapis.com/projects/proj-a/serviceAccounts/{sa_a}",
                        "assetType": "iam.googleapis.com/ServiceAccount",
                        "project": "projects/101",
                        "additionalAttributes": {"email": sa_a},
                    },
                    {
                        "name": "//compute.googleapis.com/projects/proj-a/zones/us-central1-a/instances/web-vm-1",
                        "assetType": "compute.googleapis.com/Instance",
                        "displayName": "web-vm-1",
                        "project": "projects/101",
                        "additionalAttributes": {},  # Empty additionalAttributes!
                        "versionedResources": [
                            {
                                "resource": {
                                    "name": "web-vm-1",
                                    "serviceAccounts": [{"email": vm_sa, "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
                                }
                            }
                        ],
                    },
                ]
            },
        )

    fake_gcp.add("GET", re.compile(r":searchAllResources"), handler=_resources_handler)
    fake_gcp.add(
        "GET",
        re.compile(r":searchAllIamPolicies"),
        data={
            "results": [
                {
                    # SA owned by proj-a holds a viewer binding on proj-b!
                    "resource": "//cloudresourcemanager.googleapis.com/projects/proj-b",
                    "project": "projects/202",
                    "policy": {
                        "bindings": [
                            {"role": "roles/viewer", "members": [f"serviceAccount:{sa_a}"]},
                            {"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:bob@example.com"]},
                        ]
                    },
                }
            ]
        },
    )
    fake_gcp.add("POST", re.compile(r":getIamPolicy"), data={"bindings": []})

    G, _summary = graph_mod.build_iam_privilege_graph(scope, force_refresh=True)

    # Bob has TokenCreator on proj-b ONLY -> MUST NOT have edge to sa-a (owned by proj-a)
    assert not G.has_edge("user:bob@example.com", f"serviceAccount:{sa_a}")

    # VM with SA in versioned_resource MUST have edge vm -> SA
    assert G.has_edge("vm:proj-a/web-vm-1", f"serviceAccount:{vm_sa}")
    edge_data = G.get_edge_data("vm:proj-a/web-vm-1", f"serviceAccount:{vm_sa}")
    assert edge_data["relationship"] == "Attached Runtime SA"


def test_onboarding_projects_search_fallback_excludes_other_org_and_unverifiable_projects(
    fake_gcp,
) -> None:
    fake_gcp.add(
        "GET",
        re.compile(r"organizations:search"),
        data={
            "organizations": [
                {
                    "name": "organizations/111111111111",
                    "displayName": "Target Org",
                    "state": "ACTIVE",
                }
            ]
        },
    )
    fake_gcp.add(
        "POST",
        re.compile(r"organizations:search"),
        data={
            "organizations": [
                {
                    "name": "organizations/111111111111",
                    "displayName": "Target Org",
                    "state": "ACTIVE",
                }
            ]
        },
    )
    # Force CAI searchAllResources to fail (403) so CRM v3 projects:search fallback runs
    fake_gcp.add("GET", re.compile(r":searchAllResources"), status=403, data={"error": {"message": "Permission denied"}})
    fake_gcp.add(
        "GET",
        re.compile(r"projects:search"),
        data={
            "projects": [
                {
                    "projectId": "in-target-org-direct",
                    "name": "projects/1001",
                    "state": "ACTIVE",
                    "parent": "organizations/111111111111",
                },
                {
                    "projectId": "in-target-org-folder",
                    "name": "projects/1002",
                    "state": "ACTIVE",
                    "parent": "folders/555",
                },
                {
                    "projectId": "foreign-org-project",
                    "name": "projects/9001",
                    "state": "ACTIVE",
                    "parent": "organizations/999999999999",
                },
                {
                    "projectId": "foreign-folder-project",
                    "name": "projects/9002",
                    "state": "ACTIVE",
                    "parent": "folders/999",
                },
                {
                    "projectId": "unreadable-folder-project",
                    "name": "projects/9003",
                    "state": "ACTIVE",
                    "parent": "folders/777",
                },
            ]
        },
    )
    fake_gcp.add(
        "GET",
        "https://cloudresourcemanager.googleapis.com/v3/folders/555",
        data={"name": "folders/555", "parent": "organizations/111111111111"},
    )
    fake_gcp.add(
        "GET",
        "https://cloudresourcemanager.googleapis.com/v3/folders/999",
        data={"name": "folders/999", "parent": "organizations/999999999999"},
    )
    fake_gcp.add(
        "GET",
        "https://cloudresourcemanager.googleapis.com/v3/folders/777",
        status=403,
        data={"error": {"message": "Forbidden"}},
    )

    res = onb_mod.discover_organization_hierarchy(
        organization_id="111111111111",
        ephemeral_token="fake-token",
    )
    listed_ids = {p["project_id"] for p in res["projects"]}
    assert listed_ids == {"in-target-org-direct", "in-target-org-folder"}
    assert "foreign-org-project" not in listed_ids
    assert "foreign-folder-project" not in listed_ids
    assert "unreadable-folder-project" not in listed_ids
    assert len(res["discovery_warnings"]) >= 1
