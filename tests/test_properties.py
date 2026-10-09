"""Vérifier les invariants des normaliseurs et sérialiseurs par génération de données.

Entrées : exemples Hypothesis et détections locales ; sorties : assertions
sur les noms, arguments, échappements et copies.
Sécurité : aucun accès cloud ni exécution des sources analysées ; un subprocess
Bash contrôlé exécute printf pour vérifier le quoting des arguments, tandis
que les autres propriétés manipulent les résultats de l'analyse statique.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from terraformizer.detectors._bash import flags
from terraformizer.detectors.base import slugify
from terraformizer.generators.hcl import _quote, _shell_quote, _value, deduplicate
from terraformizer.models import Finding


@settings(max_examples=200)
@given(st.text())
def test_slugify_is_a_nonempty_idempotent_identifier(value: str) -> None:
    """Un nom normalisé reste un identifiant Terraform stable."""
    result = slugify(value)
    assert re.fullmatch(r"[a-z_][a-z0-9_]*", result)
    assert result
    assert slugify(result) == result


@settings(max_examples=200)
@given(
    positionals=st.lists(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789_", min_size=1)),
    values=st.lists(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789_", min_size=1)),
)
def test_flags_preserves_positionals_and_equals_values(
    positionals: list[str], values: list[str]
) -> None:
    """Les positionnels et les valeurs explicites sont conservés."""
    words = [f"pos{index}_{word}" for index, word in enumerate(positionals)]
    expected_positionals = list(words)
    expected_values: dict[str, str] = {}
    for index, value in enumerate(values):
        if index % 2:
            key = f"equals_{index}"
            words.append(f"--{key}={value}")
            expected_values[key] = value
        else:
            key = f"value_{index}"
            words.extend((f"--{key}", value))
    words.append("--flag_without_value")

    parsed_values, parsed_positionals = flags(words)
    assert parsed_positionals == expected_positionals
    for key, value in expected_values.items():
        assert parsed_values[key] == value
    assert parsed_values["flag_without_value"] is True


@settings(max_examples=200)
@given(st.text())
def test_hcl_string_values_escape_interpolation(value: str) -> None:
    """Les chaînes HCL sont citées sans interpolation active."""
    rendered = _value(value)
    assert (
        rendered.startswith('"')
        and rendered.endswith('"')
        or rendered.startswith("<<-")
        or rendered.startswith("chomp(<<-")
    )
    assert re.search(r"(?<!\$)\$\{", rendered) is None
    assert re.search(r"(?<!%)%\{", rendered) is None
    if "\n" not in value:
        escaped = value.replace("${", "$${").replace("%{", "%%{")
        assert json.loads(_quote(value)) == escaped
        assert json.loads(rendered) == escaped


@settings(max_examples=50, deadline=None)
@given(st.text().filter(lambda value: "\0" not in value))
def test_shell_quote_round_trips_arbitrary_arguments(value: str) -> None:
    """Le quoting Bash préserve les chaînes, y compris les caractères spéciaux."""
    command = f"printf '%s' {_shell_quote(value)}"
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        check=True,
    )
    assert result.stdout == value.encode()


@settings(max_examples=200)
@given(st.lists(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-", min_size=1)))
def test_deduplicate_is_unique_and_does_not_mutate(names: list[str]) -> None:
    """La déduplication conserve chaque finding et ses données d'entrée."""
    findings = [
        Finding(
            provider="aws",
            tf_type="aws_instance",
            name=name,
            attributes={"name": name},
            source_file=Path("source.py"),
            line=index,
            original=name,
            notes=[f"note-{index}"],
        )
        for index, name in enumerate(names)
    ]
    before = copy.deepcopy(findings)

    result = deduplicate(findings)

    assert len(result) == len(findings)
    assert len({finding.address for finding in result}) == len(result)
    assert findings == before
