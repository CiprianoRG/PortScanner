#include "Analisis.h"
#include <iostream>
#include <map>
#include <algorithm>

// =====================
// MAPA DE RIESGO DE PUERTOS ( conocimiento de vulnerabilidades)
// =====================
std::map<int, int> mapaRiesgoPuertos = {
    // 🔴 CRÍTICO: Puertos de malware/backdoors conocidos
    {4444, 100}, {31337, 100}, {12345, 95}, {54321, 95}, {1337, 90},
    
    // 🔴 ALTO: Puertos de administración comúnmente atacados
    {22, 85},    // SSH - brute force
    {3389, 90},  // RDP - exploits comunes
    {23, 80},    // Telnet - sin cifrado
    {1433, 85},  // MSSQL - inyecciones
    {1521, 85},  // Oracle - vulnerabilidades
    {3306, 80},  // MySQL - ataques comunes
    
    // 🟡 MEDIO: Servicios con vulnerabilidades conocidas
    {21, 70},    // FTP - sin cifrado
    {25, 65},    // SMTP - spoofing
    {53, 60},    // DNS - poisoning
    {110, 60},   // POP3 - sin cifrado
    {143, 60},   // IMAP - sin cifrado
    
    // 🟢 BAJO: Servicios generalmente seguros
    {80, 40},    // HTTP - puede ser seguro con HTTPS
    {443, 30},   // HTTPS - generalmente seguro
    {993, 35},   // IMAPS - seguro
    {995, 35},   // POP3S - seguro
    
    // 🔵 DINÁMICOS: Puertos altos (riesgo variable)
    {10000, 50}, {20000, 50}, {30000, 45}, {40000, 45}, {50000, 40}
};

// =====================
// Calcular puntuación de riesgo
// =====================
int calcularPuntuacionRiesgo(int puerto, const std::string& servicio) {
    // 1. Buscar en mapa de riesgos conocidos
    auto it = mapaRiesgoPuertos.find(puerto);
    if (it != mapaRiesgoPuertos.end()) {
        return it->second;
    }
    
    // 2. Calcular basado en rango del puerto
    if (puerto >= 0 && puerto <= 1023) {
        return 60; // Puertos de sistema - riesgo medio
    } else if (puerto >= 1024 && puerto <= 49151) {
        return 50; // Puertos registrados - riesgo medio-bajo
    } else {
        return 40; // Puertos dinámicos - riesgo bajo
    }
}

// =====================
// Determinar nivel de riesgo based on puntuación
// =====================
NivelRiesgo determinarNivelRiesgo(int puntuacion) {
    if (puntuacion >= 90) return RIESGO_CRITICO;
    if (puntuacion >= 75) return RIESGO_ALTO;
    if (puntuacion >= 60) return RIESGO_MEDIO;
    if (puntuacion >= 40) return RIESGO_BAJO;
    return RIESGO_DESCONOCIDO;
}

// =====================
// Detectar vulnerabilidades específicas
// =====================
std::vector<std::string> detectarVulnerabilidades(int puerto, const std::string& servicio) {
    std::vector<std::string> vulnerabilidades;
    
    // Detección basada en puerto y servicio
    if (puerto == 23) vulnerabilidades.push_back("Telnet sin cifrado");
    if (puerto == 21) vulnerabilidades.push_back("FTP sin cifrado");
    if (puerto == 22) vulnerabilidades.push_back("SSH susceptible a brute force");
    if (puerto == 3389) vulnerabilidades.push_back("RDP con posibles vulnerabilidades");
    if (puerto == 1433 || puerto == 3306) {
        vulnerabilidades.push_back("Posibles inyecciones SQL");
    }
    if (puerto >= 4444 && puerto <= 4446) {
        vulnerabilidades.push_back("Puerto común de Metasploit");
    }
    if (servicio.find("HTTP") != std::string::npos && puerto != 443) {
        vulnerabilidades.push_back("HTTP sin cifrado (debería ser HTTPS)");
    }
    
    return vulnerabilidades;
}

// =====================
// Función principal de análisis automático
// =====================
std::vector<AnalisisPuerto> analizarPuertosDetallado(const std::vector<PortInfo>& puertos) {
    std::vector<AnalisisPuerto> resultados;
    
    for (const auto& puerto : puertos) {
        AnalisisPuerto analisis;
        analisis.info = puerto;
        
        // Solo analizar puertos ABIERTOS
        if (puerto.estado != "Abierto") {
            analisis.nivel_riesgo = RIESGO_BAJO;
            analisis.puntuacion_riesgo = 0;
            resultados.push_back(analisis);
            continue;
        }
        
        // Calcular riesgo
        analisis.puntuacion_riesgo = calcularPuntuacionRiesgo(puerto.port, puerto.servicio);
        analisis.nivel_riesgo = determinarNivelRiesgo(analisis.puntuacion_riesgo);
        analisis.vulnerabilidades = detectarVulnerabilidades(puerto.port, puerto.servicio);
        
        resultados.push_back(analisis);
    }
    
    return resultados;
}

// =====================
// Descripción de niveles de riesgo
// =====================
std::string obtenerDescripcionRiesgo(NivelRiesgo nivel) {
    switch (nivel) {
        case RIESGO_CRITICO: return "CRÍTICO";
        case RIESGO_ALTO: return "ALTO"; 
        case RIESGO_MEDIO: return "MEDIO";
        case RIESGO_BAJO: return "BAJO";
        case RIESGO_DESCONOCIDO: return "DESCONOCIDO";
        default: return "NO EVALUADO";
    }
}

// =====================
// Función de compatibilidad (para no romper código existente)
// =====================
void analizarPuertosSospechosos(std::vector<PortInfo>& puertos, int sensibilidad) {
    // Esta función se mantiene por compatibilidad, pero ahora usa el nuevo sistema
    auto analisis_detallado = analizarPuertosDetallado(puertos);
    
    for (size_t i = 0; i < puertos.size(); ++i) {
        // Marcar como sospechoso si tiene riesgo ALTO o CRÍTICO
        if (analisis_detallado[i].nivel_riesgo <= RIESGO_ALTO) {
            puertos[i].sospechoso = true;
            puertos[i].razon = "Riesgo: " + obtenerDescripcionRiesgo(analisis_detallado[i].nivel_riesgo);
        }
    }
}