"""
CVSSCalculator — wraps the official `cvss` PyPI package by RedHat.
Replaces our homemade CVSS math with a maintained, spec-compliant library.
pip install cvss

The `cvss` package implements CVSS v2, v3.0, v3.1, v4.0 from FIRST specification.
We wrap it to keep the same interface all phases already use.
"""
from cvss import CVSS3


# Metric abbreviations expected by the cvss package
_AV = {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P"}
_AC = {"LOW": "L", "HIGH": "H"}
_PR = {"NONE": "N", "LOW": "L", "HIGH": "H"}
_UI = {"NONE": "N", "REQUIRED": "R"}
_S  = {"UNCHANGED": "U", "CHANGED": "C"}
_C  = {"NONE": "N", "LOW": "L", "HIGH": "H"}


class CVSSCalculator:
    def calculate(self,
                  attack_vector: str       = "NETWORK",
                  attack_complexity: str   = "LOW",
                  privileges_required: str = "NONE",
                  user_interaction: str    = "NONE",
                  scope: str               = "UNCHANGED",
                  confidentiality: str     = "NONE",
                  integrity: str           = "NONE",
                  availability: str        = "NONE") -> dict:
        vector = (
            f"CVSS:3.1"
            f"/AV:{_AV[attack_vector.upper()]}"
            f"/AC:{_AC[attack_complexity.upper()]}"
            f"/PR:{_PR[privileges_required.upper()]}"
            f"/UI:{_UI[user_interaction.upper()]}"
            f"/S:{_S[scope.upper()]}"
            f"/C:{_C[confidentiality.upper()]}"
            f"/I:{_C[integrity.upper()]}"
            f"/A:{_C[availability.upper()]}"
        )
        c     = CVSS3(vector)
        score = float(c.base_score)
        if   score == 0.0:  severity = "None"
        elif score <  4.0:  severity = "Low"
        elif score <  7.0:  severity = "Medium"
        elif score <  9.0:  severity = "High"
        else:               severity = "Critical"
        return {"score": score, "vector": vector, "severity": severity}

    # ── Convenience methods (same interface as before) ────────────────────────
    def score_network_critical(self):
        return self.calculate("NETWORK","LOW","NONE","NONE","UNCHANGED","HIGH","HIGH","HIGH")
    def score_sqli(self, waf_protected=False):
        ac = "HIGH" if waf_protected else "LOW"
        return self.calculate("NETWORK",ac,"NONE","NONE","UNCHANGED","HIGH","HIGH","HIGH")
    def score_xss_reflected(self):
        return self.calculate("NETWORK","LOW","NONE","REQUIRED","CHANGED","HIGH","LOW","NONE")
    def score_xss_stored(self):
        return self.calculate("NETWORK","LOW","LOW","NONE","CHANGED","HIGH","LOW","NONE")
    def score_missing_headers(self):
        return self.calculate("NETWORK","LOW","NONE","REQUIRED","CHANGED","NONE","LOW","NONE")
    def score_exposed_file(self, contains_secrets=False):
        c = "HIGH" if contains_secrets else "LOW"
        return self.calculate("NETWORK","LOW","NONE","NONE","UNCHANGED",c,"NONE","NONE")
    def score_eol_software(self):
        return self.calculate("NETWORK","LOW","NONE","NONE","UNCHANGED","HIGH","HIGH","HIGH")
    def score_rate_limiting_missing(self):
        return self.calculate("NETWORK","LOW","NONE","NONE","UNCHANGED","HIGH","NONE","NONE")
    def score_default_credentials(self):
        return self.calculate("NETWORK","LOW","NONE","NONE","UNCHANGED","HIGH","HIGH","HIGH")
    def score_tls_critical(self):
        return self.calculate("NETWORK","HIGH","NONE","NONE","UNCHANGED","HIGH","NONE","NONE")
    def score_directory_exposed(self):
        return self.calculate("NETWORK","LOW","NONE","NONE","UNCHANGED","HIGH","NONE","NONE")

calculator = CVSSCalculator()
