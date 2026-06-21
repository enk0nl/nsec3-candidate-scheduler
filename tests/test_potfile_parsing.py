from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name
from adaptive_hashcat_scheduler.hashcat.potfile import iter_potfile_cracks


def test_potfile_parser_uses_rsplit(tmp_path, make_fake_potfile):
    pot = make_fake_potfile(tmp_path / 'run.pot', [('hash:.example.nl:salt:5', 'www')])
    assert list(iter_potfile_cracks(pot)) == [('hash:.example.nl:salt:5', 'www')]


def test_potfile_parser_preserves_multilabel_plaintext(tmp_path, make_fake_potfile):
    pot = make_fake_potfile(tmp_path / 'run.pot', [('hash:.example.nl:salt:5', 'dev.api.test')])
    assert list(iter_potfile_cracks(pot)) == [('hash:.example.nl:salt:5', 'dev.api.test')]


def test_potfile_parser_handles_plain_hash_value(tmp_path, make_fake_potfile):
    pot = make_fake_potfile(tmp_path / 'run.pot', [('abc123', 'www')])
    assert list(iter_potfile_cracks(pot)) == [('abc123', 'www')]


def test_normalize_dns_candidate_strips_trailing_dot():
    assert normalize_dns_name('Dev.Api.Test.') == 'dev.api.test'


def test_normalize_dns_candidate_rejects_empty_label():
    assert normalize_dns_name('dev..test') is None


def test_normalize_dns_candidate_allows_underscore_when_project_policy_allows_it():
    assert normalize_dns_name('_domainkey.example') == '_domainkey.example'
