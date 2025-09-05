#include "Analisis.h"
#include <iostream>
#include <map>

// =====================
// Criterios de análisis - PUERTOS CONOCIDOS DE MALWARE/RIESGO
// =====================
bool esPuertoDeMalware(int puerto) {
    // Puertos comúnmente utilizados por malware o herramientas ofensivas
    const int puertosMaliciosos[] = {
        4444, 31337, 12345, 54321, 666, 1337,  // Backdoors clásicos
        9999, 10000, 12346, 20000, 20001,      // Otros puertos sospechosos
        27374, 5074, 1234, 1999, 6711,         // Más puertos de riesgo
        8787, 1111, 2222, 3333, 5555, 7777, 8888  // Puertos consecutivos often usados
    };
    
    for (int p : puertosMaliciosos) {
        if (puerto == p) return true;
    }
    return false;
}

// =====================
// Criterios de análisis - PUERTOS DE ADMINISTRACIÓN
// =====================
bool esPuertoAdministracion(int puerto) {
    // Puertos de administración que deberían estar restringidos
    const int puertosAdmin[] = {
        22,   // SSH
        23,   // Telnet (sin cifrado!)
        3389, // RDP (Remote Desktop)
        5900, // VNC
        5432, // PostgreSQL
        3306, // MySQL
        1433, // MSSQL
        1521  // Oracle
    };
    
    for (int p : puertosAdmin) {
        if (puerto == p) return true;
    }
    return false;
}

// =====================
// Criterios de análisis - PUERTOS ALTOS INUSUALES
// =====================
bool esPuertoAltoInusual(int puerto) {
    // Puertos arriba de 10000 que no son comunes
    return (puerto > 10000 && puerto < 49152); // Puertos dinámicos/privados
}

// =====================
// Criterios de análisis - BLOQUES DE PUERTOS
// =====================
bool hayBloquePuertosAbiertos(const std::vector<PortInfo>& puertos, int inicio, int cantidad) {
    int consecutivos = 0;
    for (const auto& p : puertos) {
        if (p.estado == "Abierto") {
            consecutivos++;
            if (consecutivos >= cantidad) return true;
        } else {
            consecutivos = 0;
        }
    }
    return false;
}

// =====================
// FUNCIÓN PRINCIPAL DE ANÁLISIS
// =====================
void analizarPuertosSospechosos(std::vector<PortInfo>& puertos, NivelSensibilidad sensibilidad) {
    std::cout << "Analizando puertos con sensibilidad: " 
              << obtenerDescripcionSensibilidad(sensibilidad) << std::endl;

    for (auto& puerto : puertos) {
        if (puerto.estado != "Abierto") continue;

        // CRITERIO 1: Malware/backdoors
        if (esPuertoDeMalware(puerto.port)) {
            puerto.sospechoso = true;
            puerto.razon += "Puerto conocido de malware/backdoor; ";
        }

        // CRITERIO 2: Administración expuesta (solo en MEDIO/ALTO)
        if (sensibilidad >= MEDIO && esPuertoAdministracion(puerto.port)) {
            puerto.sospechoso = true;
            puerto.razon += "Puerto de administración expuesto; ";
        }

        // CRITERIO 3: Puertos altos inusuales (solo MEDIO/ALTO)
        if (sensibilidad >= MEDIO && esPuertoAltoInusual(puerto.port)) {
            puerto.sospechoso = true;
            puerto.razon += "Puerto alto inusual; ";
        }
    }

    // CRITERIO 4: Bloques de puertos consecutivos (solo ALTO)
    if (sensibilidad == ALTO && hayBloquePuertosAbiertos(puertos, 3)) {
        for (auto& puerto : puertos) {
            if (puerto.estado == "Abierto") {
                puerto.sospechoso = true;
                puerto.razon += "Bloque de puertos consecutivos abiertos; ";
            }
        }
    }
}

// =====================
// Función auxiliar para descripción de sensibilidad
// =====================
std::string obtenerDescripcionSensibilidad(NivelSensibilidad sensibilidad) {
    switch (sensibilidad) {
        case BAJO: return "BAJO (solo malware conocido)";
        case MEDIO: return "MEDIO (malware + admin + puertos altos)";
        case ALTO: return "ALTO (detección agresiva + bloques de puertos)";
        default: return "DESCONOCIDO";
    }
}