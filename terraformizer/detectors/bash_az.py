"""Transforme un texte shell Azure CLI en propositions de ressources ``Finding``.

Aucun shell ni appel cloud n'est exécuté, aucun fichier référencé n'est lu.
Les références HCL restent symboliques : groupes, images et identités ne sont
pas vérifiés dans Azure ; les informations manquantes sont signalées.
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
    hcl_string,
    items,
    typed_value,
)
from terraformizer.detectors.base import slugify
from terraformizer.models import Finding

# Clé : mots de sous-commande. Valeur : (type Terraform, mapping CLI → Terraform,
# attributs requis). Aucun booléen d'import : aucun ID Azure n'est déduit ici.
AZ_COMMANDS: dict[tuple[str, ...], tuple[str, dict[str, str], tuple[str, ...]]] = {
    ("group", "create"): (
        "azurerm_resource_group",
        {"name": "name", "location": "location"},
        ("name", "location"),
    ),
    # La proposition est une VM Linux ; réseau, disque et image sont complétés ensuite.
    ("vm", "create"): (
        "azurerm_linux_virtual_machine",
        {
            "name": "name",
            "size": "size",
            "admin-username": "admin_username",
            "admin-password": "admin_password",
        },
        ("name", "resource_group_name", "location", "admin_username", "network_interface_ids"),
    ),
    # Le SKU CLI combine tier et réplication, deux attributs Terraform distincts.
    ("storage", "account", "create"): (
        "azurerm_storage_account",
        {
            "name": "name",
            "kind": "account_kind",
            "https-only": "https_traffic_only_enabled",
            "min-tls-version": "min_tls_version",
            "allow-blob-public-access": "allow_nested_items_to_be_public",
        },
        ("name", "resource_group_name", "location"),
    ),
    # Les deux orthographes CLI désignent la même liste de préfixes réseau.
    ("network", "vnet", "create"): (
        "azurerm_virtual_network",
        {"name": "name", "address-prefixes": "address_space", "address-prefix": "address_space"},
        ("name", "resource_group_name", "location", "address_space"),
    ),
    # Le pool initial et l'identité exigent des blocs hors du mapping simple.
    ("aks", "create"): (
        "azurerm_kubernetes_cluster",
        {
            "name": "name",
            "dns-name-prefix": "dns_prefix",
            "kubernetes-version": "kubernetes_version",
        },
        ("name", "resource_group_name", "location", "dns_prefix", "default_node_pool"),
    ),
    # Le tenant vient d'une référence HCL, jamais de la session Azure locale.
    ("keyvault", "create"): (
        "azurerm_key_vault",
        {
            "name": "name",
            "enable-rbac-authorization": "enable_rbac_authorization",
            "enable-purge-protection": "purge_protection_enabled",
        },
        ("name", "resource_group_name", "location", "tenant_id", "sku_name"),
    ),
}

# Alias locaux → (éditeur, offre, SKU) ; aucune résolution du catalogue Azure.
IMAGES: dict[str, tuple[str, str, str]] = {
    "UbuntuLTS": ("Canonical", "0001-com-ubuntu-server-jammy", "22_04-lts"),
    "Ubuntu2204": ("Canonical", "0001-com-ubuntu-server-jammy", "22_04-lts"),
    "Ubuntu2404": ("Canonical", "ubuntu-24_04-lts", "server"),
    "Debian": ("Debian", "debian-12", "12"),
}


class BashAzDetector(BashDetector):
    """Propose les créations Azure connues avec références de groupe symboliques.

    Les IDs réseau ne sont pas inventés et les clés SSH ne sont pas générées ;
    les défauts de conversion restent soumis à une revue.
    """

    name = "bash_az"

    def detect(self, path: Path, content: str) -> list[Finding]:
        """Analyse le texte fourni sans lire ``path`` ni exécuter Azure CLI.

        Args:
            path: Chemin source conservé pour la provenance des propositions.
            content: Texte shell contenant les créations et leurs options.
        Returns:
            Propositions annotées, ou liste vide sans création reconnue.
            Images inconnues et noms réseau sans préfixe d'ID restent à renseigner.
        """
        results: list[Finding] = []
        for command in commands(content, "az"):
            words = command.words[1:]
            # Les sous-commandes ont des longueurs différentes selon la ressource.
            key = next(
                (
                    candidate
                    for candidate in AZ_COMMANDS
                    if tuple(words[: len(candidate)]) == candidate
                ),
                None,
            )
            if key is None:
                continue
            values, _ = flags(
                words[len(key) :], {"n": "name", "g": "resource-group", "l": "location"}
            )
            tf_type, mapping, required = AZ_COMMANDS[key]
            attrs: dict[str, Any] = {
                target: typed_value(target, values[source])
                for source, target in mapping.items()
                if source in values
            }
            known = set(mapping)
            notes: list[str] = []
            if tf_type != "azurerm_resource_group":
                # Référencer le groupe sans supposer qu'il existe déjà dans Azure.
                known.update({"resource-group", "location"})
                group = values.get("resource-group")
                if group:
                    address = f"azurerm_resource_group.{slugify(str(group))}"
                    attrs["resource_group_name"] = {"__raw__": f"{address}.name"}
                    attrs["location"] = values.get("location", {"__raw__": f"{address}.location"})
                elif "location" in values:
                    attrs["location"] = values["location"]
            if tf_type == "azurerm_linux_virtual_machine":
                # Azure CLI masque des blocs obligatoires de la ressource VM Linux.
                known.update(
                    {
                        "image",
                        "os-disk-name",
                        "storage-sku",
                        "nics",
                        "ssh-key-values",
                        "generate-ssh-keys",
                        "authentication-type",
                    }
                )
                # Donner des défauts locaux, sans consulter la configuration Azure.
                attrs.setdefault("size", "Standard_DS1_v2")
                attrs.setdefault("admin_username", "azureuser")
                attrs["os_disk"] = [
                    {
                        "caching": "ReadWrite",
                        "storage_account_type": values.get("storage-sku", "Standard_LRS"),
                        **({"name": values["os-disk-name"]} if "os-disk-name" in values else {}),
                    }
                ]
                # Terraform exige des IDs de NIC ; les noms seuls ne suffisent pas.
                attrs["network_interface_ids"] = items(values["nics"]) if "nics" in values else []
                if "nics" not in values:
                    notes.append(
                        "TODO : créer les interfaces réseau et renseigner "
                        "network_interface_ids ; aucun ID inventé."
                    )
                elif any(
                    not nic.startswith("/subscriptions/") for nic in attrs["network_interface_ids"]
                ):
                    attrs["network_interface_ids"] = []
                    notes.append("TODO : --nics doit contenir de vrais IDs d'interfaces réseau.")
                # Un ID va dans source_image_id ; alias/URN dans source_image_reference.
                # Un alias connu utilise latest, un URN conserve sa version explicite.
                image = str(values.get("image", "Ubuntu2204"))
                if image.startswith("/subscriptions/"):
                    attrs["source_image_id"] = image
                elif image in IMAGES:
                    publisher, offer, sku = IMAGES[image]
                    attrs["source_image_reference"] = [
                        {
                            "publisher": publisher,
                            "offer": offer,
                            "sku": sku,
                            "version": "latest",
                        }
                    ]
                elif len(image.split(":")) == 4:
                    publisher, offer, sku, version = image.split(":")
                    attrs["source_image_reference"] = [
                        {
                            "publisher": publisher,
                            "offer": offer,
                            "sku": sku,
                            "version": version,
                        }
                    ]
                else:
                    notes.append("Image Azure non reconnue : source_image_reference à renseigner.")
                if "ssh-key-values" in values:
                    # Une clé littérale reste intacte ; un chemin devient file(...) non lu.
                    public_key = str(values["ssh-key-values"])
                    if not public_key.startswith(("ssh-", "ecdsa-")):
                        key_value: Any = {"__raw__": f"file({hcl_string(public_key)})"}
                    else:
                        key_value = public_key
                    attrs["admin_ssh_key"] = [
                        {
                            "username": attrs["admin_username"],
                            "public_key": key_value,
                        }
                    ]
                elif "admin_password" not in attrs:
                    # --generate-ssh-keys ne justifie aucune génération pendant l'analyse.
                    notes.append(
                        "Attribut requis absent : admin_ssh_key ou admin_password ; "
                        "aucune clé SSH générée."
                    )
                if "admin_password" in attrs:
                    # Le mot de passe doit autoriser l'authentification correspondante.
                    attrs["disable_password_authentication"] = False
            elif tf_type == "azurerm_storage_account":
                # Standard_LRS devient tier Standard et réplication LRS ; sinon avertir.
                known.add("sku")
                sku = str(values.get("sku", "Standard_LRS"))
                parts = sku.split("_", 1)
                if len(parts) == 2 and parts[0].lower() in ("standard", "premium"):
                    attrs["account_tier"] = parts[0].capitalize()
                    attrs["account_replication_type"] = parts[1].upper()
                else:
                    notes.append("SKU Azure non reconnu : tier et réplication à renseigner.")
                attrs.setdefault("account_kind", "StorageV2")
            elif tf_type == "azurerm_virtual_network":
                # Préfixes du VNet et du sous-réseau deviennent des listes distinctes.
                known.update({"subnet-name", "subnet-prefix", "subnet-prefixes"})
                if "address_space" in attrs:
                    attrs["address_space"] = items(attrs["address_space"])
                if "subnet-name" in values:
                    subnet: dict[str, Any] = {"name": values["subnet-name"]}
                    prefix = values.get("subnet-prefixes", values.get("subnet-prefix"))
                    if prefix:
                        subnet["address_prefixes"] = items(prefix)
                    else:
                        notes.append("Attribut requis absent : subnet.address_prefixes")
                    attrs["subnet"] = [subnet]
            elif tf_type == "azurerm_kubernetes_cluster":
                # AKS requiert un pool initial ; ses paramètres CLI forment un bloc.
                known.update(
                    {
                        "node-count",
                        "node-vm-size",
                        "nodepool-name",
                        "enable-managed-identity",
                        "assign-identity",
                    }
                )
                attrs.setdefault("dns_prefix", values.get("name"))
                attrs["default_node_pool"] = [
                    {
                        "name": values.get("nodepool-name", "default"),
                        "node_count": typed_value("node_count", values.get("node-count", 3)),
                        "vm_size": values.get("node-vm-size", "Standard_DS2_v2"),
                    }
                ]
                if "assign-identity" in values:
                    # Une identité fournie impose UserAssigned et sa liste d'IDs.
                    attrs["identity"] = [
                        {"type": "UserAssigned", "identity_ids": items(values["assign-identity"])}
                    ]
                else:
                    # Sans IDs explicites, proposer une identité gérée par le système.
                    attrs["identity"] = [{"type": "SystemAssigned"}]
            elif tf_type == "azurerm_key_vault":
                # Normaliser le SKU et référencer le tenant, sans interroger la session.
                known.add("sku")
                attrs["sku_name"] = str(values.get("sku", "standard")).lower()
                attrs["tenant_id"] = {"__raw__": "data.azurerm_client_config.current.tenant_id"}
                notes.append("Déclarer data azurerm_client_config current pour obtenir tenant_id.")
            results.append(
                finding(
                    path=path,
                    command=command,
                    provider="azurerm",
                    tf_type=tf_type,
                    name=values.get("name"),
                    attributes=attrs,
                    values=values,
                    known=known,
                    ignored={"subscription", "output", "only-show-errors"},
                    required=required,
                    notes=notes,
                )
            )
        return results
