"""Détection statique des créations de ressources Google Cloud CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from terraformizer.detectors._bash import (
    BashDetector,
    commands,
    finding,
    flags,
    items,
    scalar,
    typed_value,
)
from terraformizer.models import Finding

GCLOUD_COMMANDS: dict[tuple[str, ...], tuple[str, dict[str, str], tuple[str, ...]]] = {
    ("compute", "instances", "create"): (
        "google_compute_instance",
        {
            "machine-type": "machine_type",
            "zone": "zone",
            "description": "description",
            "can-ip-forward": "can_ip_forward",
        },
        ("name", "machine_type", "zone", "boot_disk", "network_interface"),
    ),
    ("compute", "networks", "create"): (
        "google_compute_network",
        {"description": "description", "mtu": "mtu", "bgp-routing-mode": "routing_mode"},
        ("name",),
    ),
    ("compute", "firewall-rules", "create"): (
        "google_compute_firewall",
        {
            "network": "network",
            "description": "description",
            "direction": "direction",
            "priority": "priority",
            "source-ranges": "source_ranges",
            "destination-ranges": "destination_ranges",
            "source-tags": "source_tags",
            "target-tags": "target_tags",
            "disabled": "disabled",
        },
        ("name", "network"),
    ),
    ("storage", "buckets", "create"): (
        "google_storage_bucket",
        {
            "location": "location",
            "default-storage-class": "storage_class",
            "uniform-bucket-level-access": "uniform_bucket_level_access",
            "public-access-prevention": "public_access_prevention",
        },
        ("name", "location"),
    ),
    ("container", "clusters", "create"): (
        "google_container_cluster",
        {
            "zone": "location",
            "region": "location",
            "num-nodes": "initial_node_count",
            "network": "network",
            "subnetwork": "subnetwork",
        },
        ("name", "location"),
    ),
    ("sql", "instances", "create"): (
        "google_sql_database_instance",
        {"database-version": "database_version", "region": "region"},
        ("name", "database_version", "settings"),
    ),
    ("pubsub", "topics", "create"): (
        "google_pubsub_topic",
        {},
        ("name",),
    ),
    ("iam", "service-accounts", "create"): (
        "google_service_account",
        {"display-name": "display_name", "description": "description"},
        ("account_id",),
    ),
}


def _firewall_blocks(value: Any) -> list[dict[str, Any]]:
    """Groupe les ports par protocole en conservant leurs plages."""
    groups: dict[str, list[str]] = {}
    for rule in items(value):
        protocol, separator, port = rule.partition(":")
        groups.setdefault(protocol, [])
        if separator:
            groups[protocol].append(port)
    return [
        {"protocol": protocol, **({"ports": ports} if ports else {})}
        for protocol, ports in groups.items()
    ]


class BashGcloudDetector(BashDetector):
    """Convertit les commandes gcloud sans accès au compte cloud."""

    name = "bash_gcloud"

    def detect(self, path: Path, content: str) -> list[Finding]:
        """Retourne les ressources et les options nécessitant une revue."""
        results: list[Finding] = []
        for command in commands(content, "gcloud"):
            words = command.words[1:]
            while words and words[0].split("=")[0] in ("--project", "--quiet", "--format"):
                if words[0] == "--quiet" or "=" in words[0]:
                    words = words[1:]
                else:
                    words = words[2:]
            key = tuple(words[:3])
            spec = GCLOUD_COMMANDS.get(key)
            if spec is None:
                continue
            values, positional = flags(words[3:])
            tf_type, mapping, required = spec
            name = positional[0] if positional else None
            attrs: dict[str, Any] = {}
            if name:
                attrs["account_id" if tf_type == "google_service_account" else "name"] = (
                    name.removeprefix("gs://").rstrip("/")
                )
            attrs.update(
                {
                    target: typed_value(target, values[source])
                    for source, target in mapping.items()
                    if source in values
                }
            )
            known = set(mapping)
            notes: list[str] = []
            if len(positional) > 1:
                notes.append("Plusieurs noms fournis : seule la première ressource est proposée.")
            if tf_type == "google_compute_instance":
                known.update(
                    {
                        "image",
                        "image-family",
                        "image-project",
                        "boot-disk-size",
                        "boot-disk-type",
                        "network",
                        "subnet",
                        "no-address",
                        "tags",
                    }
                )
                disk: dict[str, Any] = {}
                project = values.get("image-project")
                if "image" in values:
                    image = str(values["image"])
                    disk["image"] = f"{project}/{image}" if project and "/" not in image else image
                elif "image-family" in values:
                    family = str(values["image-family"])
                    disk["image"] = f"{project}/{family}" if project else family
                    if not project:
                        notes.append("Projet de l'image absent : famille d'image à vérifier.")
                for source, target in (("boot-disk-size", "size"), ("boot-disk-type", "type")):
                    if source in values:
                        value = str(values[source]).removesuffix("GB")
                        disk[target] = (
                            typed_value("disk_size_gb", value) if target == "size" else value
                        )
                attrs["boot_disk"] = {"initialize_params": disk}
                if "image" not in disk:
                    notes.append("Attribut requis absent : boot_disk.initialize_params.image")
                interface: dict[str, Any] = {"network": values.get("network", "default")}
                if "subnet" in values:
                    interface["subnetwork"] = values["subnet"]
                if not values.get("no-address"):
                    interface["access_config"] = {}
                attrs["network_interface"] = interface
                if "tags" in values:
                    attrs["tags"] = items(values["tags"])
            elif tf_type == "google_compute_network":
                known.add("subnet-mode")
                mode = values.get("subnet-mode", "auto")
                attrs["auto_create_subnetworks"] = mode == "auto"
                if mode not in ("auto", "custom"):
                    notes.append("Mode de sous-réseau non reconnu.")
            elif tf_type == "google_compute_firewall":
                known.update({"allow", "deny"})
                attrs.setdefault("network", "default")
                for field in ("source_ranges", "destination_ranges", "source_tags", "target_tags"):
                    if field in attrs:
                        attrs[field] = items(attrs[field])
                for field in ("allow", "deny"):
                    if field in values:
                        attrs[field] = _firewall_blocks(values[field])
                if "allow" not in attrs and "deny" not in attrs:
                    notes.append("Attribut requis absent : allow ou deny")
            elif tf_type == "google_container_cluster":
                known.update({"machine-type", "disk-size", "enable-autopilot"})
                if "machine-type" in values or "disk-size" in values:
                    node_config = {
                        target: typed_value(target, values[source])
                        for source, target in (
                            ("machine-type", "machine_type"),
                            ("disk-size", "disk_size_gb"),
                        )
                        if source in values
                    }
                    attrs["node_config"] = node_config
                if "enable-autopilot" in values:
                    attrs["enable_autopilot"] = scalar(values["enable-autopilot"])
            elif tf_type == "google_sql_database_instance":
                known.add("tier")
                if "tier" in values:
                    attrs["settings"] = {"tier": values["tier"]}
            results.append(
                finding(
                    path=path,
                    command=command,
                    provider="google",
                    tf_type=tf_type,
                    name=name,
                    attributes=attrs,
                    values=values,
                    known=known,
                    ignored={"project", "quiet", "format"},
                    required=required,
                    import_id=(
                        str(attrs["name"])
                        if tf_type == "google_storage_bucket" and attrs.get("name")
                        else None
                    ),
                    notes=notes,
                )
            )
        return results
