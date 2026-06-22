from __future__ import annotations

from adaptive_hashcat_scheduler.arms.dictionary import DictionaryArm
from adaptive_hashcat_scheduler.arms.brute_force import BruteForceArm
from adaptive_hashcat_scheduler.arms.feedback_common import CommonFeedbackArm
from adaptive_hashcat_scheduler.arms.feedback_predictive import PredictiveFeedbackArm
from adaptive_hashcat_scheduler.arms.permutation import PermutationArm
from adaptive_hashcat_scheduler.arms.static_affix_feedback import StaticAffixFeedbackArm
from adaptive_hashcat_scheduler.arms.parent_domain_feedback import ParentDomainFeedbackArm
from adaptive_hashcat_scheduler.arms.amass_osint import AmassOsintArm
from adaptive_hashcat_scheduler.arms.subfinder_osint import SubfinderOsintArm

ARM_TYPES = {
    'dictionary': DictionaryArm,
    'brute_force': BruteForceArm,
    'feedback': CommonFeedbackArm,
    'predictive_prefix': PredictiveFeedbackArm,
    'predictive_suffix': PredictiveFeedbackArm,
    'permutation': PermutationArm,
    'static_affix_feedback': StaticAffixFeedbackArm,
    'parent_domain_feedback': ParentDomainFeedbackArm,
    'amass_osint': AmassOsintArm,
    'subfinder_osint': SubfinderOsintArm,
}

FEEDBACK_TYPES = {'feedback', 'predictive_prefix', 'predictive_suffix', 'permutation', 'static_affix_feedback', 'parent_domain_feedback'}
OSINT_TYPES = {'amass_osint', 'subfinder_osint'}
SUPPORTED_ARM_TYPES = set(ARM_TYPES)


def make_arm(cfg):
    arm_type = cfg['type']
    try:
        cls = ARM_TYPES[arm_type]
    except KeyError as exc:
        raise ValueError(f'unknown arm type: {arm_type}') from exc
    return cls(cfg['name'], arm_type, cfg)
