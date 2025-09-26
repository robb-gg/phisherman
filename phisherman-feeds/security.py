"""Seguridad para microservicio interno - solo red interna."""

import logging

from fastapi import HTTPException, Request

from .config import feeds_settings

logger = logging.getLogger(__name__)


async def verify_internal_access(request: Request) -> bool:
    """
    Verificar que la request viene de un servicio interno autorizado.

    En production esto debería usar:
    - Headers de autenticación interna
    - Certificados mTLS
    - Network policies de Kubernetes

    Para desarrollo verificamos host/IP básico.
    """
    # Obtener información del cliente
    client_host = request.client.host if request.client else "unknown"
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    host_header = request.headers.get("Host", "")
    user_agent = request.headers.get("User-Agent", "")

    logger.debug(
        f"Internal access check - Host: {client_host}, "
        f"X-Forwarded-For: {forwarded_for}, Host Header: {host_header}"
    )

    # En desarrollo, permitir hosts locales
    if not feeds_settings.is_production:
        allowed_hosts = feeds_settings.allowed_internal_hosts

        # Verificar host directo
        if client_host in allowed_hosts:
            return True

        # Verificar host header (para docker compose)
        if any(allowed in host_header for allowed in allowed_hosts):
            return True

        # Verificar X-Forwarded-For
        if forwarded_for and any(allowed in forwarded_for for allowed in allowed_hosts):
            return True

    # En producción, verificar headers específicos o certificados
    else:
        # Header interno personalizado
        internal_token = request.headers.get("X-Internal-Service-Token")
        if internal_token == feeds_settings.secret_key:
            return True

        # Verificar User-Agent específico del servicio principal
        if "Phisherman-API" in user_agent:
            return True

    # Si llegamos aquí, denegar acceso
    logger.warning(
        f"Access denied from {client_host} - "
        f"Host: {host_header}, User-Agent: {user_agent}"
    )

    raise HTTPException(
        status_code=403, detail="Access denied - internal services only"
    )
