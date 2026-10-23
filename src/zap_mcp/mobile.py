"""Prepara um aparelho/emulador Android (via ADB) para o ZAP inspecionar o
trafego do app mobile do usuario — inclusive apps Flutter.

Contexto: o Flutter nao usa o proxy do sistema e nao confia na CA que o usuario
instala (o Dart tem o proprio armazenamento TLS, via BoringSSL). Entao, para um
app Flutter, nao basta "setar o proxy": e preciso (1) instalar a CA do ZAP no
armazenamento do SISTEMA (aparelho rooted ou emulador) e (2) redirecionar o
trafego de forma transparente (iptables) para o ZAP em modo transparente — e,
quando o app fixa/ignora a CA, desligar essa verificacao no app com reFlutter ou
Frida. Este modulo cobre o setup com ADB (listar aparelho, instalar a CA, proxy,
redirect) e entrega o passo a passo do resto. So opera via o binario adb
(ADB_PATH); se faltar, devolve erro claro. Use so no SEU aparelho e no SEU app.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


class MobileError(Exception):
    """ADB ausente, aparelho nao encontrado ou comando falhou."""


def _run(path: str, args: list[str], timeout: float = 30.0) -> tuple[int, str, str]:
    try:
        p = subprocess.run(  # noqa: S603 - path do .env, args controlados
            [path, *args], capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise MobileError(
            f"'{path}' nao encontrado. Instale o platform-tools do Android ou "
            f"defina ADB_PATH."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise MobileError(f"adb {' '.join(args)} passou de {timeout}s") from exc
    return p.returncode, p.stdout or "", p.stderr or ""


def _dev_args(serial: str) -> list[str]:
    return ["-s", serial] if serial else []


def version(path: str) -> str:
    """Versao do adb (primeira linha). Levanta MobileError se faltar."""
    _, out, _ = _run(path, ["version"])
    return out.splitlines()[0].strip() if out else "desconhecida"


def devices(path: str) -> list[dict]:
    """Aparelhos conectados: [{serial, state, model}]. Ignora o cabecalho."""
    _, out, _ = _run(path, ["devices", "-l"])
    found = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        serial, state = parts[0], (parts[1] if len(parts) > 1 else "?")
        model = next((p.split(":", 1)[1] for p in parts if p.startswith("model:")), "")
        found.append({"serial": serial, "state": state, "model": model})
    return found


def _one_device(path: str, serial: str) -> str:
    devs = [d for d in devices(path) if d["state"] == "device"]
    if serial:
        if not any(d["serial"] == serial for d in devs):
            raise MobileError(f"aparelho '{serial}' nao esta conectado/autorizado.")
        return serial
    if not devs:
        raise MobileError("nenhum aparelho conectado (adb devices vazio).")
    if len(devs) > 1:
        raise MobileError("varios aparelhos conectados — informe o serial.")
    return devs[0]["serial"]


def set_proxy(path: str, host: str, port: int, serial: str = "") -> dict:
    """Define o proxy HTTP global do Android (host:porta do ZAP).

    Vale para WebViews e apps que respeitam o proxy do sistema. O Flutter ignora
    isto — para ele e preciso o redirect transparente (transparent_redirect).
    """
    serial = _one_device(path, serial)
    target = f"{host}:{port}"
    code, _, err = _run(path, [*_dev_args(serial), "shell", "settings", "put",
                               "global", "http_proxy", target])
    if code != 0:
        raise MobileError(f"falha ao setar o proxy: {err.strip()}")
    return {"serial": serial, "http_proxy": target,
            "nota": "WebViews/apps nativos passam a usar o ZAP. Flutter NAO — use o redirect."}


def clear_proxy(path: str, serial: str = "") -> dict:
    """Remove o proxy HTTP global do Android."""
    serial = _one_device(path, serial)
    _run(path, [*_dev_args(serial), "shell", "settings", "put", "global", "http_proxy", ":0"])
    _run(path, [*_dev_args(serial), "shell", "settings", "delete", "global", "http_proxy"])
    return {"serial": serial, "http_proxy": "removido"}


def cert_hash_name(ca_pem: str, openssl: str = "openssl") -> str | None:
    """Nome que o Android espera no system store: <subject_hash_old>.0.

    Usa o openssl (subject_hash_old). Se faltar, devolve None e o usuario instala
    a CA pela tela de Configuracoes (armazenamento do usuario).
    """
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(ca_pem)
            pem_path = f.name
        p = subprocess.run(  # noqa: S603 - openssl do sistema, arquivo temporario
            [openssl, "x509", "-inform", "PEM", "-subject_hash_old", "-in", pem_path],
            capture_output=True, text=True, timeout=15,
        )
        Path(pem_path).unlink(missing_ok=True)
        first = (p.stdout or "").splitlines()
        return f"{first[0].strip()}.0" if first and first[0].strip() else None
    except Exception:  # noqa: BLE001 - openssl e opcional
        return None


def install_ca(path: str, ca_pem: str, serial: str = "", openssl: str = "openssl") -> dict:
    """Envia a CA do ZAP para o aparelho e devolve os proximos passos.

    Manda o PEM para /sdcard/Download/zap-ca.crt (para instalar pela tela, no
    armazenamento do USUARIO) e calcula o nome do system store (<hash>.0) para
    quem tem root/emulador. O Flutter so confia na CA do SISTEMA.
    """
    serial = _one_device(path, serial)
    with tempfile.NamedTemporaryFile("w", suffix=".crt", delete=False) as f:
        f.write(ca_pem)
        local = f.name
    dest = "/sdcard/Download/zap-ca.crt"
    code, _, err = _run(path, [*_dev_args(serial), "push", local, dest])
    Path(local).unlink(missing_ok=True)
    if code != 0:
        raise MobileError(f"falha no adb push: {err.strip()}")
    hashed = cert_hash_name(ca_pem, openssl)
    passos = [
        f"Usuario: no aparelho, Configuracoes > Seguranca > Instalar certificado "
        f"> CA, escolha {dest}.",
    ]
    if hashed:
        passos.append(
            f"Sistema (root/emulador): adb -s {serial} root && adb remount && "
            f"adb push {dest} /system/etc/security/cacerts/{hashed} && "
            f"adb shell chmod 644 /system/etc/security/cacerts/{hashed}"
        )
    passos.append("Flutter so confia na CA do SISTEMA — a instalacao do usuario "
                  "nao basta para um app Flutter.")
    return {"serial": serial, "pushed_to": dest, "system_store_name": hashed,
            "passos": passos}


def transparent_redirect(path: str, zap_host: str, zap_port: int, serial: str = "",
                         ports: tuple[int, ...] = (80, 443)) -> dict:
    """Redireciona (iptables, via su) o trafego do aparelho para o ZAP transparente.

    PRECISA de root. O Flutter ignora o proxy do sistema, entao este redirect e o
    que faz o trafego dele chegar no ZAP. O ZAP tem que estar em modo transparente
    escutando em zap_host:zap_port, alcancavel pela rede do aparelho.
    """
    serial = _one_device(path, serial)
    rules = [
        f"iptables -t nat -A OUTPUT -p tcp --dport {p} -j DNAT "
        f"--to-destination {zap_host}:{zap_port}"
        for p in ports
    ]
    ran, errors = [], []
    for rule in rules:
        code, _, err = _run(path, [*_dev_args(serial), "shell", "su", "-c", rule])
        ran.append(rule)
        if code != 0:
            errors.append(err.strip() or f"falha na regra: {rule}")
    return {"serial": serial, "zap": f"{zap_host}:{zap_port}", "rules": ran,
            "errors": errors,
            "ok": not errors,
            "nota": "Precisa de root. Sem erros = trafego redirecionado ao ZAP."}


def guidance() -> dict:
    """Passo a passo para testar um app Flutter com o ZAP (sem rodar nada)."""
    return {
        "titulo": "Testar um app Flutter com o ZAP",
        "porque": (
            "O Flutter nao usa o proxy do sistema e tem o proprio armazenamento "
            "TLS (BoringSSL): nao confia na CA que o usuario instala. Por isso o "
            "caminho normal de proxy nao funciona para ele."
        ),
        "passos": [
            "1. Use um emulador ou um aparelho COM ROOT (so o system store vale).",
            "2. Instale a CA do ZAP no armazenamento do SISTEMA (botao Instalar CA).",
            "3. Deixe o ZAP em modo transparente, alcancavel pela rede do aparelho.",
            "4. Redirecione o trafego (botao Redirect transparente / iptables).",
            "5. Se o app fixa ou ignora a CA, desligue a verificacao no app com "
            "reFlutter (repackaging do APK) ou Frida (hook em runtime) — so no SEU app.",
            "6. Abra o app; o trafego aparece no ZAP (get_urls/alerts).",
        ],
        "ferramentas_externas": ["reFlutter", "Frida", "ZAP modo transparente"],
    }


def status(path: str) -> dict:
    """Resumo para o painel: adb disponivel, versao e aparelhos."""
    v = version(path)
    return {"available": True, "version": v, "devices": devices(path)}
