"""The words of the demo's server-rendered screens, in English and Portuguese, and the labels of what each
credential holds. The page itself has its own copy in static/i18n.js."""

from __future__ import annotations

from typing import Any

LANGUAGES = ("en", "pt")

TEXT: dict[str, dict[str, str]] = {
    "en": {
        "brand": "FOAAP demo issuer",
        "demo_notice": "A demonstration: the people are fictional and no identity is checked.",
        "login_title": "Sign in",
        "login_intro": "Your wallet asked {issuer} for {credentials}. Choose who you are in this demo.",
        "login_persona": "Sign in as",
        "continue": "Continue",
        "cancel": "Cancel",
        "consent_title": "Issue to your wallet?",
        "consent_intro": "{issuer} will issue {credentials} to {wallet}. This is what it will hold:",
        "consent_hold": "Hold it for the operator's review first (deferred issuance)",
        "consent_hold_hint": "The wallet is told to come back later; the demo page lets you release or refuse it.",
        "issue": "Issue",
        "error_title": "This sign-in cannot go on",
        "error_gone": "It expired or was already used. Start again in your wallet.",
        "error_unavailable": "The issuer is not reachable right now. Try again in a minute.",
        "error_formats": "Ask for one format of the course certificate at a time.",
        "error_request": "Something in this request was not right. Start again in your wallet.",
        "error_busy": "Too many requests from your network. Try again in a minute.",
        "your_wallet": "your wallet",
        "pid_issuer": "the FOAAP demo PID issuer",
        "course_issuer": "FOAAP Academy (demo)",
        "pid": "a person identification (PID)",
        "course": "a course certificate",
        "language": "Português",
        "onward_title": "Back to your wallet",
        "onward": "Continue",
    },
    "pt": {
        "brand": "Emissor de demonstração FOAAP",
        "demo_notice": "Uma demonstração: as pessoas são fictícias e nenhuma identidade é verificada.",
        "login_title": "Entrar",
        "login_intro": "A sua carteira pediu a {issuer} {credentials}. Escolha quem é nesta demonstração.",
        "login_persona": "Entrar como",
        "continue": "Continuar",
        "cancel": "Cancelar",
        "consent_title": "Emitir para a sua carteira?",
        "consent_intro": "{issuer} vai emitir {credentials} para {wallet}. É isto que vai conter:",
        "consent_hold": "Reter primeiro para revisão do operador (emissão diferida)",
        "consent_hold_hint": "A carteira volta mais tarde; a página da demonstração deixa-o libertar ou recusar.",
        "issue": "Emitir",
        "error_title": "Esta autenticação não pode continuar",
        "error_gone": "Expirou ou já foi usada. Comece de novo na sua carteira.",
        "error_unavailable": "O emissor não está acessível neste momento. Tente de novo dentro de um minuto.",
        "error_formats": "Peça um formato do certificado de curso de cada vez.",
        "error_request": "Algo neste pedido não estava certo. Comece de novo na sua carteira.",
        "error_busy": "Demasiados pedidos a partir da sua rede. Tente de novo dentro de um minuto.",
        "your_wallet": "a sua carteira",
        "pid_issuer": "o emissor de PID de demonstração FOAAP",
        "course_issuer": "a FOAAP Academy (demonstração)",
        "pid": "uma identificação pessoal (PID)",
        "course": "um certificado de curso",
        "language": "English",
        "onward_title": "De volta à sua carteira",
        "onward": "Continuar",
    },
}

LABELS: dict[str, dict[str, str]] = {
    "en": {
        "family_name": "Family name",
        "given_name": "Given name",
        "birthdate": "Date of birth",
        "place_of_birth": "Place of birth",
        "nationalities": "Nationality",
        "issuing_country": "Issuing country",
        "issuing_authority": "Issued by",
        "date_of_expiry": "Valid until",
        "achievement_title": "Course",
        "achievement_description": "Description",
        "learning_outcomes": "Learning outcomes",
        "assessment_grade": "Grade",
        "language_of_classes": "Language of the course",
        "expected_study_time": "Study time",
        "ects_credits": "ECTS credits",
        "level_of_learning_experience": "EQF level",
        "course_provider": "Course provider",
        "course_url": "Course page",
        "date_of_completion": "Completed on",
    },
    "pt": {
        "family_name": "Apelido",
        "given_name": "Nome próprio",
        "birthdate": "Data de nascimento",
        "place_of_birth": "Local de nascimento",
        "nationalities": "Nacionalidade",
        "issuing_country": "País emissor",
        "issuing_authority": "Emitido por",
        "date_of_expiry": "Válido até",
        "achievement_title": "Curso",
        "achievement_description": "Descrição",
        "learning_outcomes": "Resultados de aprendizagem",
        "assessment_grade": "Classificação",
        "language_of_classes": "Língua do curso",
        "expected_study_time": "Tempo de estudo",
        "ects_credits": "Créditos ECTS",
        "level_of_learning_experience": "Nível QEQ",
        "course_provider": "Entidade formadora",
        "course_url": "Página do curso",
        "date_of_completion": "Concluído em",
    },
}


def language(query: str | None, accept: str | None) -> str:
    """?lang= first, then the browser's Accept-Language: Portuguese if it comes before English, else English."""
    if query in LANGUAGES:
        return str(query)
    for part in (accept or "").split(","):
        tag = part.split(";")[0].strip().lower()
        if tag.startswith("pt"):
            return "pt"
        if tag.startswith("en"):
            return "en"
    return "en"


def shown(value: Any) -> str:
    """A claim's value as one line of text: a place as its parts, a list joined."""
    if isinstance(value, dict):
        return ", ".join(str(v) for v in value.values())
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)
