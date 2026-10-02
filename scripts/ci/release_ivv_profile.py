"""Select only separately reviewed intermediate plans; never infer eligibility."""
from dataclasses import dataclass
from importlib import import_module

try:
    from scripts.ci import release_ivv_plan as frozen
except ModuleNotFoundError:
    import release_ivv_plan as frozen

# Explicit identities prevent an unknown release from inheriting a prior verdict.
REVIEWED = {
    'v4.10.0': ('release_ivv_current', 'current_candidate_update_verify',
               '.github/workflows/release-ivv.yml',
               '8c3405758a9b369924f466d12652e99d3a84dc56'),
    'v4.10.1': ('release_ivv_v4101', 'candidate_update_verify_v4101',
               '.github/workflows/release-ivv-v4101.yml',
               '8611c84cb8c245195dd5456bebad13a52b1d7217'),
    'v4.10.2': ('release_ivv_v4102', 'candidate_update_verify_v4102',
               '.github/workflows/release-ivv-v4102.yml',
               '94d97f07cb5a054669dd66d6efd28ba55db5d173'),
}


@dataclass(frozen=True)
class Profile:
    current: object
    updater: object
    workflow: str
    product: str


def load(release: str) -> Profile:
    frozen.require(type(release) is str and release in REVIEWED,
                   'no reviewed intermediate product plan for this release')
    current_name, updater_name, workflow, product = REVIEWED[release]
    prefix = __package__ + '.' if __package__ else ''
    current = import_module(prefix + current_name)
    updater = import_module(prefix + updater_name)
    plan = current.load_plan()
    frozen.require(plan['release'] == release and plan['required_assurance'] == 'IVV'
                   and current.PRODUCT == product and plan['product_candidate'] == product,
                   'reviewed intermediate profile identity differs')
    return Profile(current, updater, workflow, product)
