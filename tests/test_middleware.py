"""Tests unitarios del middleware Wazuh-LLM."""
import json
import pytest
import requests
from unittest.mock import patch, MagicMock

from wazuh_llm.threat_hunting import reparar_json_truncado
import wazuh_llm.middleware as mw


class TestRepararJsonTruncado:
    def test_json_completo_no_modifica(self):
        entrada = '{"query": {"match_all": {}}}'
        assert reparar_json_truncado(entrada) == entrada

    def test_cierra_llave_faltante(self):
        reparado = reparar_json_truncado('{"query": {"bool": {"must": [')
        json.loads(reparado)  # debe ser JSON válido

    def test_cierra_multiples_niveles(self):
        assert reparar_json_truncado('{"a": {"b": [') == '{"a": {"b": []}}'

    def test_no_afecta_llaves_dentro_de_string(self):
        entrada = '{"key": "valor con { corchete"}'
        assert reparar_json_truncado(entrada) == entrada

    def test_json_vacio(self):
        assert reparar_json_truncado('') == ''


class TestGuardrailSeguridad:
    def test_ip_loopback_en_plan_respuesta_activa_guardrail(self):
        informe = "PLAN DE RESPUESTA:\n  Ejecutar iptables -A INPUT -s 127.0.0.1 -j DROP\n"
        assert "GUARDRAIL ACTIVADO" in mw.validar_respuesta_ia(informe)

    def test_ip_loopback_ipv6_activa_guardrail(self):
        informe = "RESPUESTA ACTIVA:\n  ufw deny from ::1\n"
        assert "GUARDRAIL ACTIVADO" in mw.validar_respuesta_ia(informe)

    def test_ip_externa_legitima_no_activa_guardrail(self):
        informe = "PLAN DE RESPUESTA:\n  iptables -A INPUT -s 45.33.32.156 -j DROP\n"
        assert "GUARDRAIL ACTIVADO" not in mw.validar_respuesta_ia(informe)

    def test_informe_sin_seccion_respuesta_no_activa_guardrail(self):
        informe = (
            "RESUMEN: El atacante intentó acceder desde 127.0.0.1.\n"
            "No se recomienda ninguna acción automática.\n"
        )
        assert "GUARDRAIL ACTIVADO" not in mw.validar_respuesta_ia(informe)


class TestObtenerAlertasDelIndexer:
    def _mock_indexer_ok(self, alertas: list) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "hits": {"hits": [{"_source": a} for a in alertas]}
        }
        return mock_resp

    @patch("wazuh_llm.middleware.requests.post")
    def test_parsea_correctamente_hits(self, mock_post):
        alerta = {"rule": {"id": "5710", "level": 10}, "data": {"srcip": "45.33.32.156"}}
        mock_post.return_value = self._mock_indexer_ok([alerta])
        resultados = mw.obtener_alertas_del_indexer(n_alertas=1)
        assert len(resultados) == 1
        assert resultados[0]["rule"]["id"] == "5710"

    @patch("wazuh_llm.middleware.requests.post")
    def test_devuelve_lista_vacia_si_no_hay_alertas(self, mock_post):
        mock_post.return_value = self._mock_indexer_ok([])
        assert mw.obtener_alertas_del_indexer() == []

    @patch("wazuh_llm.middleware.requests.post")
    def test_devuelve_lista_vacia_si_status_no_200(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_post.return_value = mock_resp
        assert mw.obtener_alertas_del_indexer() == []

    @patch("wazuh_llm.middleware.requests.post",
           side_effect=requests.exceptions.ConnectionError)
    def test_devuelve_lista_vacia_si_indexer_no_disponible(self, mock_post):
        assert mw.obtener_alertas_del_indexer() == []
