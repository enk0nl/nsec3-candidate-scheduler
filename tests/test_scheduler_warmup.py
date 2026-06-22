import json

from nsec3_candidate_scheduler.arms.brute_force import BruteForceArm
from nsec3_candidate_scheduler.arms.dictionary import DictionaryArm
from nsec3_candidate_scheduler.arms.parent_domain_feedback import ParentDomainFeedbackArm
from nsec3_candidate_scheduler.arms.permutation import PermutationArm
from nsec3_candidate_scheduler.arms.static_affix_feedback import StaticAffixFeedbackArm
from nsec3_candidate_scheduler.config import load_config
from nsec3_candidate_scheduler.scheduler import make_arm


def test_feedback_arms_not_warmup_eligible(tmp_path, write_lines):
    wordlist = tmp_path / 'words.txt'; write_lines(wordlist, ['www'])
    prefixes = tmp_path / 'prefixes.txt'; suffixes = tmp_path / 'suffixes.txt'
    write_lines(prefixes, ['dev']); write_lines(suffixes, ['internal'])
    model = tmp_path / 'model.tsv'; write_lines(model, ['api\tdev\t1'])
    configs = [
        {'name': 'seclists', 'type': 'dictionary', 'wordlist': str(wordlist)},
        {'name': 'pcfg', 'type': 'dictionary', 'wordlist': str(wordlist)},
        {'name': 'brute_force', 'type': 'brute_force'},
        {'name': 'predictive-prefix', 'type': 'predictive_prefix', 'model': str(model)},
        {'name': 'predictive-suffix', 'type': 'predictive_suffix', 'model': str(model)},
        {'name': 'permutation', 'type': 'permutation'},
        {'name': 'static-affix-top50', 'type': 'static_affix_feedback', 'prefixes': str(prefixes), 'suffixes': str(suffixes)},
        {'name': 'parent-domain', 'type': 'parent_domain_feedback'},
    ]
    arms = [make_arm(cfg) for cfg in configs]
    assert [arm.name for arm in arms if arm.warmup_eligible] == ['seclists', 'pcfg', 'brute_force']


def test_feedback_arms_observe_shared_new_discoveries_during_warmup(tmp_path, make_context):
    ctx = make_context(tmp_path)
    parent = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    metrics = parent.on_new_discoveries(['dev.api.test'], ctx)
    assert parent.warmup_eligible is False
    assert metrics['parent_candidates_enqueued'] == 2
    assert parent._queue(ctx).load_queue() == ['api.test', 'test']


def test_warmup_arm_local_default_when_config_missing(tmp_path, write_lines):
    wordlist = tmp_path / 'words.txt'; write_lines(wordlist, ['www'])
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'arms': [{'name': 'seclists', 'type': 'dictionary', 'wordlist': str(wordlist)}]}), encoding='utf-8')
    assert load_config(str(config))['warmup']['scoring'] == 'arm_local'


def test_warmup_shared_marginal_config_still_supported(tmp_path, write_lines):
    wordlist = tmp_path / 'words.txt'; write_lines(wordlist, ['www'])
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'warmup': {'scoring': 'shared_marginal'}, 'arms': [{'name': 'seclists', 'type': 'dictionary', 'wordlist': str(wordlist)}]}), encoding='utf-8')
    assert load_config(str(config))['warmup']['scoring'] == 'shared_marginal'
