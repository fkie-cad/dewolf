from cvpipeline.corpus import DedupResult, deduplicate, group_by_binary, make_key, parse_key


def test_key_roundtrip_with_cpp_names():
    key = make_key("proj", "bin", "ns::Class::method")
    assert parse_key(key) == ("proj", "bin", "ns::Class::method")


def test_duplicates_within_a_project_keep_alphabetically_first():
    fingerprints = {"p": {"b1": {"f": "X", "g": "Y"}, "a0": {"h": "X"}}}
    result = deduplicate(fingerprints)
    assert result.kept == sorted([make_key("p", "a0", "h"), make_key("p", "b1", "g")])
    assert result.excluded == {make_key("p", "b1", "f"): make_key("p", "a0", "h")}


def test_fingerprint_claimed_by_earlier_project_is_excluded_in_later_one():
    fingerprints = {
        "zeta": {"b": {"shared": "S", "own": "Z"}},
        "alpha": {"b": {"shared": "S"}},
    }
    result = deduplicate(fingerprints)
    assert make_key("alpha", "b", "shared") in result.kept
    assert make_key("zeta", "b", "shared") not in result.kept
    assert result.excluded[make_key("zeta", "b", "shared")] == make_key("alpha", "b", "shared")
    assert make_key("zeta", "b", "own") in result.kept


def test_unfingerprinted_functions_are_always_kept():
    fingerprints = {"p": {"b": {"f": None, "g": None, "h": "X"}}, "q": {"b": {"f": None}}}
    result = deduplicate(fingerprints)
    assert len(result.kept) == 4
    assert result.unfingerprinted == 3
    assert result.excluded == {}


def test_result_independent_of_input_order():
    a = {"p": {"b": {"f": "X", "g": "X"}}, "q": {"c": {"h": "X"}}}
    b = {"q": {"c": {"h": "X"}}, "p": {"b": {"g": "X", "f": "X"}}}
    assert deduplicate(a) == deduplicate(b)


def test_json_roundtrip():
    result = deduplicate({"p": {"b": {"f": "X", "g": "X", "h": None}}})
    assert DedupResult.from_json(result.to_json()) == result


def test_group_by_binary():
    keys = [make_key("p", "b", "z"), make_key("p", "b", "a"), make_key("q", "c", "m")]
    assert group_by_binary(keys) == {("p", "b"): ["a", "z"], ("q", "c"): ["m"]}
