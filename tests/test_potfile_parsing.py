from nsec3_candidate_scheduler.feedback.normalize import normalize_dns_name
from nsec3_candidate_scheduler.hashcat.potfile import iter_potfile_cracks


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


def test_iter_potfile_cracks_preserves_empty_plaintext_when_allowed(tmp_path):
    pot = tmp_path / 'run.pot'
    pot.write_text('7c33954r9727aj5urd7blat7nm4deftv:.example.nl:ab:1:\n', encoding='utf-8')
    assert list(iter_potfile_cracks(pot, allow_empty_plaintext=True)) == [
        ('7c33954r9727aj5urd7blat7nm4deftv:.example.nl:ab:1', '')
    ]


def test_iter_potfile_cracks_preserves_space_empty_plaintext_when_allowed(tmp_path):
    pot = tmp_path / 'run.pot'
    pot.write_text('7c33954r9727aj5urd7blat7nm4deftv:.example.nl:ab:1: \n', encoding='utf-8')
    assert list(iter_potfile_cracks(pot, allow_empty_plaintext=True)) == [
        ('7c33954r9727aj5urd7blat7nm4deftv:.example.nl:ab:1', '')
    ]


def test_iter_potfile_cracks_drops_empty_plaintext_when_not_allowed(tmp_path):
    pot = tmp_path / 'run.pot'
    pot.write_text('7c33954r9727aj5urd7blat7nm4deftv:.example.nl:ab:1:\n', encoding='utf-8')
    assert list(iter_potfile_cracks(pot, allow_empty_plaintext=False)) == []


def test_potfile_parser_uses_rsplit_for_mode_8300(tmp_path):
    pot = tmp_path / 'run.pot'
    pot.write_text('abcd1234:.example.nl:ab:1:www\n', encoding='utf-8')
    assert list(iter_potfile_cracks(pot)) == [('abcd1234:.example.nl:ab:1', 'www')]


def test_invalid_empty_line_still_ignored(tmp_path):
    pot = tmp_path / 'run.pot'
    pot.write_text('\nmalformed-without-colon\n', encoding='utf-8')
    assert list(iter_potfile_cracks(pot, allow_empty_plaintext=True)) == []
