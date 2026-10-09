"""Transforme un texte shell gcloud en propositions de ressources ``Finding``.

Aucun shell ni appel cloud n'est exécuté, aucun fichier référencé n'est lu.
Les créations inconnues sont ignorées ; les options non traduites et les champs
manquants sont signalés plutôt que résolus auprès d'un projet Google Cloud.
La reconnaissance est heuristique, pas une interprétation complète du langage shell.
"""

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

# Clé : mots de sous-commande. Valeur : (type Terraform, mapping CLI → Terraform,
# attributs requis). Aucun champ booléen d'import : seul le bucket est traité ensuite.
GCLOUD_COMMANDS: dict[tuple[str, ...], tuple[str, dict[str, str], tuple[str, ...]]] = {
    # Disque et interface sont des blocs, assemblés après les champs simples.
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
    # Le mode de sous-réseau CLI devient un booléen hors de ce mapping.
    ("compute", "networks", "create"): (
        "google_compute_network",
        {"description": "description", "mtu": "mtu", "bgp-routing-mode": "routing_mode"},
        ("name",),
    ),
    # --allow/--deny regroupent protocoles et ports, pas des attributs scalaires.
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
    # L'URI gs:// positionnelle fournit le nom et l'ID d'import après nettoyage.
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
    # Zone et région alimentent la même location ; aucun arbitrage cloud.
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
    # Le tier appartient au bloc settings, complété dans le post-traitement.
    ("sql", "instances", "create"): (
        "google_sql_database_instance",
        {"database-version": "database_version", "region": "region"},
        ("name", "database_version", "settings"),
    ),
    # Le nom positionnel suffit aux attributs, pas à déduire un import qualifié.
    ("pubsub", "topics", "create"): (
        "google_pubsub_topic",
        {},
        ("name",),
    ),
    # Le nom positionnel est account_id, pas un nom complet de compte de service.
    ("iam", "service-accounts", "create"): (
        "google_service_account",
        {"display-name": "display_name", "description": "description"},
        ("account_id",),
    ),
}


def _firewall_blocks(value: Any) -> list[dict[str, Any]]:
    """Regroupe les règles CLI en blocs Terraform par protocole.

    Args:
        value: Tokens ou texte séparé par espaces/virgules, par exemple tcp:80-90.
    Returns:
        Blocs avec plages intactes ; sans champ ports si aucun port n'est fourni.
        Les protocoles et ports ne sont pas validés auprès du cloud.
    """
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
    """Propose les créations gcloud connues sans consulter le projet courant.

    Les défauts locaux sont explicites ; les valeurs shell et options restantes
    nécessitent une revue plutôt qu'une exécution de la CLI.
    """

    name = "bash_gcloud"

    def detect(self, path: Path, content: str) -> list[Finding]:
        """Analyse le texte fourni sans lire ``path`` ni exécuter gcloud.

        Args:
            path: Chemin source conservé pour la provenance.
            content: Texte shell contenant les commandes à reconnaître.
        Returns:
            Propositions annotées, ou liste vide sans création reconnue.
            Plusieurs noms produisent une seule proposition avec avertissement.
        """
        results: list[Finding] = []
        for command in commands(content, "gcloud"):
            words = command.words[1:]
            # Accepter les options globales initiales sans consulter la configuration CLI.
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
            # Le nom est positionnel ; les buckets retirent leur préfixe d'URI.
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
                # Disque d'amorçage et réseau sont requis sous forme de blocs Terraform.
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
                # Qualifier seulement les images non déjà qualifiées par un chemin.
                if "image" in values:
                    image = str(values["image"])
                    disk["image"] = f"{project}/{image}" if project and "/" not in image else image
                elif "image-family" in values:
                    family = str(values["image-family"])
                    disk["image"] = f"{project}/{family}" if project else family
                    if not project:
                        notes.append("Projet de l'image absent : famille d'image à vérifier.")
                # Terraform attend une taille numérique, sans suffixe CLI « GB ».
                for source, target in (("boot-disk-size", "size"), ("boot-disk-type", "type")):
                    if source in values:
                        value = str(values[source]).removesuffix("GB")
                        disk[target] = (
                            typed_value("disk_size_gb", value) if target == "size" else value
                        )
                attrs["boot_disk"] = {"initialize_params": disk}
                if "image" not in disk:
                    notes.append("Attribut requis absent : boot_disk.initialize_params.image")
                # access_config vide demande une IP externe ; --no-address l'omet.
                interface: dict[str, Any] = {"network": values.get("network", "default")}
                if "subnet" in values:
                    interface["subnetwork"] = values["subnet"]
                if not values.get("no-address"):
                    interface["access_config"] = {}
                attrs["network_interface"] = interface
                # Les tags réseau gcloud deviennent une liste, même pour un tag unique.
                if "tags" in values:
                    attrs["tags"] = items(values["tags"])
            elif tf_type == "google_compute_network":
                # auto crée les sous-réseaux ; custom laisse leur création explicite.
                known.add("subnet-mode")
                mode = values.get("subnet-mode", "auto")
                attrs["auto_create_subnetworks"] = mode == "auto"
                if mode not in ("auto", "custom"):
                    notes.append("Mode de sous-réseau non reconnu.")
            elif tf_type == "google_compute_firewall":
                # Les sélecteurs sont des listes ; allow/deny des blocs par protocole.
                known.update({"allow", "deny"})
                attrs.setdefault("network", "default")
                for field in ("source_ranges", "destination_ranges", "source_tags", "target_tags"):
                    if field in attrs:
                        attrs[field] = items(attrs[field])
                for field in ("allow", "deny"):
                    if field in values:
                        attrs[field] = _firewall_blocks(values[field])
                # Sans action, une règle ne décrit pas ce qui doit être filtré.
                if "allow" not in attrs and "deny" not in attrs:
                    notes.append("Attribut requis absent : allow ou deny")
            elif tf_type == "google_container_cluster":
                # Les paramètres des nœuds appartiennent à node_config, pas au cluster.
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
                # Conserver le booléen Autopilot sans inférer les choix de nœuds du service.
                if "enable-autopilot" in values:
                    attrs["enable_autopilot"] = scalar(values["enable-autopilot"])
            elif tf_type == "google_sql_database_instance":
                # settings reste absent sans tier, afin de signaler le prérequis manquant.
                known.add("tier")
                if "tier" in values:
                    attrs["settings"] = {"tier": values["tier"]}
            # Seul le nom du bucket suffit ici à un import sans identité de projet.
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
