"""Migration script: transforms dashboard.json into multi-cluster datas/ structure."""
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATAS_DIR = os.path.join(BASE_DIR, 'datas')
CLUSTER_ID = 'CLP'
CLUSTER_DIR = os.path.join(DATAS_DIR, CLUSTER_ID)
AUTOSCORE_DIR = os.path.join(CLUSTER_DIR, 'autoscore')
SOURCE_FILE = os.path.join(BASE_DIR, 'dashboard.json')

DEFAULT_CONFIG = {
    "groups": [
        {
            "name": "APPLICATIONS", "color": "grey",
            "columns": [
                {"field": "nom", "label": "Nom", "type": "text", "hasLink": True, "filterable": True},
                {"field": "code", "label": "Code", "type": "text", "filterable": True},
                {"field": "equipe", "label": "\u00c9quipe", "type": "text", "filterable": True},
                {"field": "os", "label": "OS", "type": "toggle", "values": ["", "UNIX", "WINDOWS", "MAINFRAME", "KUBE"], "filterable": True},
                {"field": "zone", "label": "Zone", "type": "toggle", "values": ["", "3PG", "TARGET2", "COMMUNAUTAIRE"], "filterable": True}
            ]
        },
        {
            "name": "AUTOSCORE", "color": "pink",
            "columns": [
                {"field": "note", "label": "Note (A-G)", "type": "autoscore", "format": "note", "filterable": True},
                {"field": "score", "label": "Score (/660)", "type": "autoscore", "format": "score", "filterable": True}
            ]
        },
        {
            "name": "AUTOMATISATION / TOIL", "color": "blue",
            "columns": [
                {"field": "priority", "label": "Priorit\u00e9", "type": "toggle", "values": ["", "P0", "P1", "P2", "P3", "P4"], "filterable": True, "format": "priority"},
                {"field": "stop", "label": "Stop", "type": "toggle", "values": ["", "AUTO", "MANUEL"], "filterable": True, "format": "status"},
                {"field": "start", "label": "Start", "type": "toggle", "values": ["", "AUTO", "MANUEL"], "filterable": True, "format": "status"},
                {"field": "status", "label": "Status", "type": "toggle", "values": ["", "AUTO", "MANUEL"], "filterable": True, "format": "status"},
                {"field": "prisePreuve", "label": "Prise preuve PSI", "type": "toggle", "values": ["", "AUTO", "MANUEL"], "filterable": True, "format": "status"},
                {"field": "deployApp", "label": "Deploy Applicatif", "type": "toggle", "values": ["", "AUTO", "MANUEL"], "filterable": True, "format": "status"},
                {"field": "deployBout", "label": "Deploy Bout en Bout", "type": "toggle", "values": ["", "AUTO", "MANUEL"], "filterable": True, "format": "status"},
                {"field": "patchMgt", "label": "Patch Mgt", "type": "toggle", "values": ["", "AUTO", "MANUEL"], "filterable": True, "format": "status"},
                {"field": "blackout", "label": "Blackout Superv.", "type": "toggle", "values": ["", "AUTO", "MANUEL"], "filterable": True, "format": "status"},
                {"field": "artifactory", "label": "Livraison via Artifactory", "type": "toggle", "values": ["", "OUI", "NON"], "filterable": True, "format": "status"}
            ]
        },
        {
            "name": "OBSERVABILITE", "color": "green",
            "columns": [
                {"field": "dynaHP", "label": "Dynatrace Install en HP", "type": "toggle", "values": ["", "INFRAO", "NON", "FSTACK"], "filterable": True, "format": "status"},
                {"field": "dynaProd", "label": "Dynatrace Install en Prod", "type": "toggle", "values": ["", "INFRAO", "NON", "FSTACK"], "filterable": True, "format": "status"},
                {"field": "dashDyna", "label": "Dashboard Dynatrace", "type": "toggle", "values": ["", "OUI", "NON"], "filterable": True, "format": "status"},
                {"field": "elisa", "label": "Puit de logs ELISA", "type": "toggle", "values": ["", "OUI", "NON", "PARTIEL"], "filterable": True, "format": "status"}
            ]
        },
        {
            "name": "DISPONIBILITE", "color": "yellow",
            "columns": [
                {"field": "sla", "label": "SLA (%)", "type": "text", "filterable": True, "format": "sla"},
                {"field": "dashSLx", "label": "Dash SLx", "type": "toggle", "values": ["", "OUI", "NON"], "filterable": True, "format": "status"},
                {"field": "errorBudget", "label": "Error Budget", "type": "toggle", "values": ["", "OUI", "NON"], "filterable": True, "format": "status"}
            ]
        }
    ],
    "valueColors": {
        "AUTO": {"bg": "#66bb6a", "fg": "white"},
        "MANUEL": {"bg": "#dc3545", "fg": "white"},
        "INFRAO": {"bg": "#ff9800", "fg": "white"},
        "FSTACK": {"bg": "#66bb6a", "fg": "white"},
        "OUI": {"bg": "#66bb6a", "fg": "white"},
        "NON": {"bg": "#dc3545", "fg": "white"},
        "PARTIEL": {"bg": "#ff9800", "fg": "white"},
        "P0": {"bg": "#b71c1c", "fg": "white"},
        "P1": {"bg": "#dc3545", "fg": "white"},
        "P2": {"bg": "#ff9800", "fg": "white"},
        "P3": {"bg": "#fdd835", "fg": "#333"},
        "P4": {"bg": "#66bb6a", "fg": "white"}
    },
    "groupColors": {
        "grey":   {"header": "#6c757d", "subHeader": "#9e9e9e", "cell": "#e0e0e0"},
        "pink":   {"header": "#ec407a", "subHeader": "#f06292", "cell": "#f8bbd0"},
        "blue":   {"header": "#42a5f5", "subHeader": "#64b5f6", "cell": "#bbdefb"},
        "green":  {"header": "#66bb6a", "subHeader": "#81c784", "cell": "#c8e6c9"},
        "yellow": {"header": "#fdd835", "subHeader": "#ffeb3b", "cell": "#fff9c4"}
    },
    "noteThresholds": [
        {"min": 600, "note": "A"}, {"min": 550, "note": "B"}, {"min": 500, "note": "C"},
        {"min": 400, "note": "D"}, {"min": 300, "note": "E"}, {"min": 200, "note": "F"},
        {"min": 0, "note": "G"}
    ],
    "slaThresholds": [
        {"min": 99.9, "color": "green"}, {"min": 99.0, "color": "orange"}, {"min": 0, "color": "red"}
    ],
    "addRowFields": [
        {"field": "nom", "type": "input", "placeholder": "Nom", "required": True},
        {"field": "code", "type": "input", "placeholder": "Code", "required": True},
        {"field": "equipe", "type": "input", "placeholder": "\u00c9quipe", "required": True},
        {"field": "os", "type": "select", "placeholder": "-- OS --", "options": ["UNIX", "WINDOWS", "MAINFRAME", "KUBE"]},
        {"field": "zone", "type": "select", "placeholder": "-- Zone --", "options": ["3PG", "TARGET2", "COMMUNAUTAIRE"]}
    ]
}

DEFAULT_CAD_CONFIG = {
    "groups": [
        {
            "name": "APPLICATION", "color": "grey",
            "columns": [
                {"field": "nom", "label": "Nom", "type": "text", "hasLink": True, "filterable": True},
                {"field": "code", "label": "Code", "type": "text", "filterable": True},
                {"field": "equipe", "label": "\u00c9quipe", "type": "text", "filterable": True},
                {"field": "domaine", "label": "Domaine", "type": "toggle", "values": ["", "Paiement", "Cr\u00e9dit", "\u00c9pargne", "Assurance", "RH", "Transverse"], "filterable": True},
                {"field": "criticite", "label": "Criticit\u00e9", "type": "toggle", "values": ["", "C1", "C2", "C3", "C4"], "filterable": True, "format": "priority"}
            ]
        },
        {
            "name": "ARCHITECTURE", "color": "blue",
            "columns": [
                {"field": "typeArchi", "label": "Type Architecture", "type": "toggle", "values": ["", "Microservices", "Monolithe", "SOA", "Batch", "Hybride"], "filterable": True, "format": "status"},
                {"field": "conformite", "label": "Conformit\u00e9 Cible", "type": "toggle", "values": ["", "Conforme", "En cours", "Non conforme", "N/A"], "filterable": True, "format": "status"},
                {"field": "urbanisation", "label": "Urbanisation", "type": "toggle", "values": ["", "OK", "KO", "En cours"], "filterable": True, "format": "status"},
                {"field": "apis", "label": "APIs", "type": "toggle", "values": ["", "REST", "SOAP", "GraphQL", "Aucune"], "filterable": True, "format": "status"},
                {"field": "documentation", "label": "Documentation", "type": "toggle", "values": ["", "\u00c0 jour", "Obsol\u00e8te", "Manquante"], "filterable": True, "format": "status"}
            ]
        },
        {
            "name": "TECHNIQUE", "color": "green",
            "columns": [
                {"field": "stack", "label": "Stack", "type": "toggle", "values": ["", "Java", ".NET", "Python", "COBOL", "Angular", "React", "Autre"], "filterable": True},
                {"field": "bdd", "label": "Base de donn\u00e9es", "type": "toggle", "values": ["", "Oracle", "PostgreSQL", "MongoDB", "DB2", "Autre"], "filterable": True},
                {"field": "middleware", "label": "Middleware", "type": "toggle", "values": ["", "Tomcat", "WebSphere", "JBoss", "Nginx", "Autre"], "filterable": True},
                {"field": "conteneurise", "label": "Conteneuris\u00e9", "type": "toggle", "values": ["", "OUI", "NON", "En cours"], "filterable": True, "format": "status"}
            ]
        },
        {
            "name": "H\u00c9BERGEMENT", "color": "pink",
            "columns": [
                {"field": "zoneHeberg", "label": "Zone", "type": "toggle", "values": ["", "On-Premise", "Cloud Priv\u00e9", "Cloud Public", "Hybride"], "filterable": True},
                {"field": "pra", "label": "PRA", "type": "toggle", "values": ["", "OK", "KO", "N/A"], "filterable": True, "format": "status"},
                {"field": "pca", "label": "PCA", "type": "toggle", "values": ["", "OK", "KO", "N/A"], "filterable": True, "format": "status"},
                {"field": "scalabilite", "label": "Scalabilit\u00e9", "type": "toggle", "values": ["", "Horizontale", "Verticale", "Aucune"], "filterable": True}
            ]
        },
        {
            "name": "CONFORMIT\u00c9", "color": "yellow",
            "columns": [
                {"field": "securite", "label": "S\u00e9curit\u00e9", "type": "toggle", "values": ["", "Valid\u00e9", "Non valid\u00e9", "En cours"], "filterable": True, "format": "status"},
                {"field": "rgpd", "label": "RGPD", "type": "toggle", "values": ["", "Conforme", "Non conforme", "En cours"], "filterable": True, "format": "status"},
                {"field": "obsolescence", "label": "Obsolescence", "type": "toggle", "values": ["", "OK", "\u00c0 risque", "Critique"], "filterable": True, "format": "status"},
                {"field": "dernierAudit", "label": "Dernier Audit", "type": "text", "filterable": True}
            ]
        }
    ],
    "valueColors": {
        "C1": {"bg": "#b71c1c", "fg": "white"},
        "C2": {"bg": "#dc3545", "fg": "white"},
        "C3": {"bg": "#ff9800", "fg": "white"},
        "C4": {"bg": "#66bb6a", "fg": "white"},
        "Conforme": {"bg": "#66bb6a", "fg": "white"},
        "Non conforme": {"bg": "#dc3545", "fg": "white"},
        "En cours": {"bg": "#ff9800", "fg": "white"},
        "OK": {"bg": "#66bb6a", "fg": "white"},
        "KO": {"bg": "#dc3545", "fg": "white"},
        "OUI": {"bg": "#66bb6a", "fg": "white"},
        "NON": {"bg": "#dc3545", "fg": "white"},
        "Valid\u00e9": {"bg": "#66bb6a", "fg": "white"},
        "Non valid\u00e9": {"bg": "#dc3545", "fg": "white"},
        "\u00c0 jour": {"bg": "#66bb6a", "fg": "white"},
        "Obsol\u00e8te": {"bg": "#ff9800", "fg": "white"},
        "Manquante": {"bg": "#dc3545", "fg": "white"},
        "\u00c0 risque": {"bg": "#ff9800", "fg": "white"},
        "Critique": {"bg": "#b71c1c", "fg": "white"},
        "N/A": {"bg": "#9e9e9e", "fg": "white"},
        "Microservices": {"bg": "#42a5f5", "fg": "white"},
        "Monolithe": {"bg": "#ff9800", "fg": "white"},
        "REST": {"bg": "#42a5f5", "fg": "white"},
        "SOAP": {"bg": "#ff9800", "fg": "white"},
        "GraphQL": {"bg": "#ab47bc", "fg": "white"}
    },
    "groupColors": {
        "grey":   {"header": "#6c757d", "subHeader": "#9e9e9e", "cell": "#e0e0e0"},
        "pink":   {"header": "#ec407a", "subHeader": "#f06292", "cell": "#f8bbd0"},
        "blue":   {"header": "#42a5f5", "subHeader": "#64b5f6", "cell": "#bbdefb"},
        "green":  {"header": "#66bb6a", "subHeader": "#81c784", "cell": "#c8e6c9"},
        "yellow": {"header": "#fdd835", "subHeader": "#ffeb3b", "cell": "#fff9c4"}
    },
    "noteThresholds": [],
    "slaThresholds": [],
    "addRowFields": [
        {"field": "nom", "type": "input", "placeholder": "Nom", "required": True},
        {"field": "code", "type": "input", "placeholder": "Code", "required": True},
        {"field": "equipe", "type": "input", "placeholder": "\u00c9quipe", "required": True},
        {"field": "domaine", "type": "select", "placeholder": "-- Domaine --", "options": ["Paiement", "Cr\u00e9dit", "\u00c9pargne", "Assurance", "RH", "Transverse"]},
        {"field": "criticite", "type": "select", "placeholder": "-- Criticit\u00e9 --", "options": ["C1", "C2", "C3", "C4"]}
    ]
}


DEFAULT_AUTOSCORE_CONFIG = {
    "categories": [
        {
            "id": "autom", "name": "Automatisation", "color": "#1565c0",
            "criteria": [
                {"id": "A1", "question": "Quelles sont les pratiques d'automatisation :", "options": [
                    {"label": "Sysadmin (tout est manuel)", "score": 0},
                    {"label": "Scripting (Bash, Ksh, Zsh, Powershell \u2026)", "score": 3},
                    {"label": "Infra as code (AAP, AWX, K8S, Openshift, Terraform)", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "A2", "question": "Quel est le pourcentage d'automatisation :", "options": [
                    {"label": "Moins de 25%", "score": 0},
                    {"label": "De 25 \u00e0 50%", "score": 2},
                    {"label": "De 50 \u00e0 75%", "score": 7},
                    {"label": "Plus de 75 %", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "A3", "question": "Quelle est la dur\u00e9e de reconstruction d'une VM ou conteneur :", "options": [
                    {"label": "Plus de 24h", "score": 0},
                    {"label": "De 1h \u00e0 24h", "score": 2},
                    {"label": "De 5 min \u00e0 1h", "score": 5},
                    {"label": "Moins de 5 min", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "A4", "question": "L'ensemble des changements \"standards\" sont automatis\u00e9s :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "A5", "question": "Le d\u00e9ploiement applicatif est automatis\u00e9 :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "A6", "question": "Le patching OS et Middleware est automatis\u00e9 :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "A7", "question": "Les actes d'exploitation sont-ils automatis\u00e9s (reprise, status, arret/relance \u2026) :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "A8", "question": "Le niveau de toil (charge d'exploitation, processus manuels \u2026) repr\u00e9sente pour l'\u00e9quipe :", "options": [
                    {"label": "Plus de 75 % de la charge des Ops", "score": 0},
                    {"label": "De 50 \u00e0 75%", "score": 2},
                    {"label": "De 25 \u00e0 50%", "score": 7},
                    {"label": "Moins de 25%", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "A9", "question": "Une chaine de CI/CD est utilis\u00e9e en mode :", "options": [
                    {"label": "Il n'y a pas de chaine de CI/CD (tout se fait manuellement)", "score": 0},
                    {"label": "Int\u00e9gration Continue (test, build, package)", "score": 2},
                    {"label": "D\u00e9ploiement Continue (en hors-prod)", "score": 7},
                    {"label": "D\u00e9ploiement Continue (en prod)", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "A10", "question": "La pyramide des tests est respect\u00e9e et d\u00e9clench\u00e9e de mani\u00e8re auto en CI/CD :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "A11", "question": "La capacit\u00e9 de d\u00e9ploiement en production est de :", "options": [
                    {"label": "Plusieurs fois par an", "score": 0},
                    {"label": "Plusieurs fois par mois", "score": 2},
                    {"label": "Plusieurs fois par semaine", "score": 7},
                    {"label": "Plusieurs fois par jour", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "A12", "question": "Chaque package applicatif est immuable, sign\u00e9 et stock\u00e9 sur Artifactory afin d'\u00eatre d\u00e9ploy\u00e9 de l'int\u00e9gration \u00e0 la production sans modification :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "A13", "question": "Le code d'automatisation est idempotent :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "A14", "question": "Le code d'automatisation est valid\u00e9 via des tests unitaires :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "A15", "question": "Le code d'automatisation est v\u00e9rifi\u00e9 via un linter :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "A16", "question": "Les r\u00e8gles de nommage AAP et Artifactory sont respect\u00e9es :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]}
            ]
        },
        {
            "id": "dispo", "name": "Disponibilit\u00e9", "color": "#2e7d32",
            "criteria": [
                {"id": "D1", "question": "La gestion des incidents est structur\u00e9e via la d\u00e9marche ITIL (priorisation, CCO \u2026)", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "D2", "question": "Le(s) SLA est d\u00e9fini et suivi", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "D3", "question": "Le(s) SLO est d\u00e9fini et suivi", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "D4", "question": "Les SLI sont d\u00e9finis et mesur\u00e9s", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "D5", "question": "L'Error Budget est calcul\u00e9 (delta entre SLA/SLO et SLI)", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "D6", "question": "L'architecture est HA et les golden rules sont respect\u00e9es", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "D7", "question": "Les SLA ont \u00e9t\u00e9 respect\u00e9s \u00e0 100% sur les 12 derniers mois", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "D8", "question": "Les SLO ont \u00e9t\u00e9 respect\u00e9s \u00e0 100% sur les 12 derniers mois", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "D9", "question": "L'Error Budget est utilis\u00e9 pour arbitrer l'\u00e9quilibre entre stabilit\u00e9 et agilit\u00e9 et 100% des \u00e9volutions pr\u00e9vues ont pu \u00eatre d\u00e9ploy\u00e9es sur les 12 derniers mois", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "D10", "question": "Du Chaos Engineering est mis en place afin de tester la r\u00e9silience du service complet et de chaque composant", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]}
            ]
        },
        {
            "id": "observ", "name": "Observabilit\u00e9", "color": "#e65100",
            "criteria": [
                {"id": "O1", "question": "Les logs sont collect\u00e9s dans un puit de logs :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O2", "question": "Les niveaux de logs respectent les bonnes pratiques :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O3", "question": "L'application engendre-t-elle des erreurs \"normales\" (r\u00e9currentes et non trait\u00e9es) :", "options": [
                    {"label": "Oui", "score": 0}, {"label": "Non", "score": 10}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O4", "question": "Un incident est cr\u00e9\u00e9 en cas d'exception applicative :", "options": [
                    {"label": "Non", "score": 0},
                    {"label": "1 incident par Exception (doublons possibles)", "score": 5},
                    {"label": "1 incident par s\u00e9rie d'exceptions (\u00e9vitant les doublons)", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "O5", "question": "Les m\u00e9triques syst\u00e8mes (cpu, ram, disk) sont collect\u00e9s dans un outil de supervision :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O6", "question": "Les m\u00e9triques middleware (tps r\u00e9ponses, latence \u2026) sont collect\u00e9s dans un outil de supervision :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O7", "question": "Les m\u00e9triques transactionnel (dur\u00e9e, traffic, taux d'erreur ...) sont collect\u00e9s dans un outil de supervision :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O8", "question": "Dynatrace est install\u00e9 :", "options": [
                    {"label": "Non", "score": 0},
                    {"label": "Oui en InfraOnly uniquement", "score": 2},
                    {"label": "Oui en InfraOnly et FullStack", "score": 7},
                    {"label": "Oui tout est en FullStack", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "O9", "question": "Un dashboard expose une vue synth\u00e9tique et centralis\u00e9e de l'\u00e9tat du service (m\u00e9triques, erreurs \u2026) :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O10", "question": "Un dashboard expose les SLI / SLO / SLA :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O11", "question": "Les rootcauses sont d\u00e9tect\u00e9es via un probl\u00e8me g\u00e9n\u00e9r\u00e9 par IA :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O12", "question": "Les signaux faibles sont d\u00e9tect\u00e9s de mani\u00e8re pro-active :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O13", "question": "Une alerte est envoy\u00e9e aux RA pour chaque anomalie (signaux faibles, erreurs \u2026)", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O14", "question": "Certains incidents sont pr\u00e9visibles par la corr\u00e9lation des donn\u00e9es techniques et m\u00e9tier :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "O15", "question": "Les principaux incidents sont autor\u00e9m\u00e9di\u00e9s :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]}
            ]
        },
        {
            "id": "amelior", "name": "Am\u00e9lioration Continue", "color": "#6a1b9a",
            "criteria": [
                {"id": "AC1", "question": "Les crit\u00e8res d'acceptances de l'application sont d\u00e9finis et respect\u00e9s pour passer en production :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "AC2", "question": "La root-cause des incidents est d\u00e9termin\u00e9e via un postmortem :", "options": [
                    {"label": "Non", "score": 0},
                    {"label": "Oui, les incidents P1 \u00e0 P2", "score": 5},
                    {"label": "Oui, les incidents P1 \u00e0 P4", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "AC3", "question": "Au moins 20% du temps des Ops est d\u00e9di\u00e9 \u00e0 l'am\u00e9lioration continue :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "AC4", "question": "Une culture sans reproche (blameless) est la norme :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "AC5", "question": "La suppression des interventions manuelles est vis\u00e9e pour chaque \u00e9volution :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "AC6", "question": "La simplicit\u00e9 des processus est vis\u00e9e pour chaque \u00e9volution :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "AC7", "question": "La revue de code est institu\u00e9e dans les pratiques de l'\u00e9quipe :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "AC8", "question": "Le partage de connaissance permet de diffuser les comp\u00e9tences :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "AC9", "question": "Un r\u00e9f\u00e9rentiel des erreurs applicatives et solutions sp\u00e9cifiques est maintenu :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "AC10", "question": "Un catalogue des erreurs / solutions g\u00e9n\u00e9riques est maintenu et partag\u00e9 :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "AC11", "question": "Un processus de pilotage du toil est mis en place :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "AC12", "question": "Le nombre d'incidents est mesur\u00e9 :", "options": [
                    {"label": "Non", "score": 0},
                    {"label": "Oui et la tendance est en hausse", "score": 3},
                    {"label": "Oui et la tendance est stable ou en baisse", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "AC13", "question": "Le nombre d'astreintes est mesur\u00e9 :", "options": [
                    {"label": "Non", "score": 0},
                    {"label": "Oui et la tendance est en hausse", "score": 3},
                    {"label": "Oui et la tendance est stable ou en baisse", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "AC14", "question": "La dette technique est mesur\u00e9e :", "options": [
                    {"label": "Non", "score": 0},
                    {"label": "Oui et la tendance est en hausse", "score": 3},
                    {"label": "Oui et la tendance est stable ou en baisse", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "AC15", "question": "Le taux d'obsolescence est mesur\u00e9 :", "options": [
                    {"label": "Non", "score": 0},
                    {"label": "Oui et la tendance est en hausse", "score": 3},
                    {"label": "Oui et la tendance est stable ou en baisse", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "AC16", "question": "La documentation est pr\u00e9cise, compl\u00e8te, bien organis\u00e9e et accessible :", "options": [
                    {"label": "Non", "score": 0},
                    {"label": "Partiellement", "score": 3},
                    {"label": "Oui", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "AC17", "question": "Le marquage syst\u00e9matique des faux-positifs et faux n\u00e9gatifs est r\u00e9alis\u00e9 :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "AC18", "question": "Une alerte est remont\u00e9e au management si les moyens ne permettent pas d'atteindre les objectifs :", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]}
            ]
        },
        {
            "id": "collab", "name": "Collaboration", "color": "#00838f",
            "criteria": [
                {"id": "C1", "question": "Les Dev et les Ops travaillent dans la m\u00eame \u00e9quipe", "options": [
                    {"label": "Non", "score": 0},
                    {"label": "Oui mais des diff\u00e9rences perdurent (outils unifi\u00e9s, habilitations, p\u00e9rim\u00e8tre de responsabilit\u00e9s ...)", "score": 3},
                    {"label": "Oui et il n'y a pas de diff\u00e9rence entre les Dev et les Ops", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "C2", "question": "Les d\u00e9veloppeurs et les OPS sont colocalis\u00e9s", "options": [
                    {"label": "Non", "score": 0},
                    {"label": "Oui, partiellement", "score": 5},
                    {"label": "Oui, dans le m\u00eame bureau", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "C3", "question": "L'ensemble des caf\u00e9s d\u00e9couvertes SRE ont \u00e9t\u00e9 suivis par l'\u00e9quipe", "options": [
                    {"label": "0 % de l'\u00e9quipe", "score": 0},
                    {"label": "25% de l'\u00e9quipe", "score": 2},
                    {"label": "50% de l'\u00e9quipe", "score": 5},
                    {"label": "75% de l'\u00e9quipe", "score": 7},
                    {"label": "100% de l'\u00e9quipe", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "C4", "question": "La formation SRE Niveau 1 a \u00e9t\u00e9 suivie par l'\u00e9quipe", "options": [
                    {"label": "0 % de l'\u00e9quipe", "score": 0},
                    {"label": "25% de l'\u00e9quipe", "score": 2},
                    {"label": "50% de l'\u00e9quipe", "score": 5},
                    {"label": "75% de l'\u00e9quipe", "score": 7},
                    {"label": "100% de l'\u00e9quipe", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "C5", "question": "L'ensemble des niveaux cibles (par profils) ont \u00e9t\u00e9 atteints par l'\u00e9quipe", "options": [
                    {"label": "0 % de l'\u00e9quipe", "score": 0},
                    {"label": "25% de l'\u00e9quipe", "score": 2},
                    {"label": "50% de l'\u00e9quipe", "score": 5},
                    {"label": "75% de l'\u00e9quipe", "score": 7},
                    {"label": "100% de l'\u00e9quipe", "score": 10},
                    {"label": "n/a", "score": 10}
                ]},
                {"id": "C6", "question": "L'arbre de d\u00e9cision d'appel au support AppOps est connu et respect\u00e9", "options": [
                    {"label": "Oui", "score": 10}, {"label": "Non", "score": 0}, {"label": "n/a", "score": 10}
                ]},
                {"id": "C7", "question": "La posture SRE est en place dans l'\u00e9quipe", "options": [
                    {"label": "Aucun r\u00e9f\u00e9rent SRE", "score": 0},
                    {"label": "Un r\u00e9f\u00e9rent SRE est identifi\u00e9", "score": 2},
                    {"label": "Un r\u00e9f\u00e9rent SRE porte le sujet dans l'\u00e9quipe", "score": 5},
                    {"label": "L'ensemble de l'\u00e9quipe est autonome sur le SRE", "score": 10},
                    {"label": "n/a", "score": 10}
                ]}
            ]
        }
    ]
}


def migrate():
    if not os.path.exists(SOURCE_FILE):
        print(f"ERROR: {SOURCE_FILE} not found")
        return

    # Create directories
    os.makedirs(AUTOSCORE_DIR, exist_ok=True)
    print(f"Created: {AUTOSCORE_DIR}")

    # Write clusters.json
    clusters = [{"id": CLUSTER_ID, "name": "CLP", "description": "Cluster CLP", "created": "2026-02-28"}]
    clusters_path = os.path.join(DATAS_DIR, 'clusters.json')
    with open(clusters_path, 'w', encoding='utf-8') as f:
        json.dump(clusters, f, ensure_ascii=False, indent=2)
    print(f"Written: {clusters_path}")

    # Read source data
    with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
        apps = json.load(f)
    print(f"Read {len(apps)} apps from {SOURCE_FILE}")

    # Extract autoscore data and clean apps
    autoscore_count = 0
    for app in apps:
        if 'autoscore' in app and app['autoscore']:
            code = app.get('code', '')
            if code:
                as_path = os.path.join(AUTOSCORE_DIR, f'{code}.json')
                with open(as_path, 'w', encoding='utf-8') as f:
                    json.dump(app['autoscore'], f, ensure_ascii=False, indent=2)
                autoscore_count += 1
            del app['autoscore']
        # Ensure standard keys exist
        for key in ['comments', 'alerts', 'reminders', 'coaching']:
            if key not in app:
                app[key] = {}

    print(f"Extracted {autoscore_count} autoscore files to {AUTOSCORE_DIR}")

    # Write data.json
    data_path = os.path.join(CLUSTER_DIR, 'data.json')
    with open(data_path, 'w', encoding='utf-8') as f:
        json.dump(apps, f, ensure_ascii=False, indent=2)
    print(f"Written: {data_path} ({len(apps)} apps)")

    # Write config.json
    config_path = os.path.join(CLUSTER_DIR, 'config.json')
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(DEFAULT_CONFIG, f, ensure_ascii=False, indent=2)
    print(f"Written: {config_path}")

    print("\nMigration complete!")


if __name__ == '__main__':
    migrate()
