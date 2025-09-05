#ifndef ANALISIS_H
#define ANALISIS_H

#include <vector>
#include "EstrategiaEscaneo.h"  // Incluimos para usar la estructura PortInfo

// =====================
// Niveles de sensibilidad para el análisis
// =====================
enum NivelSensibilidad {
    BAJO = 0,    // Menos detecciones, solo lo más obvio
    MEDIO = 1,   // Detecciones balanceadas  
    ALTO = 2     // Máximas detecciones (puede haber falsos positivos)
};

// =====================
// Funciones públicas del módulo de Análisis
// =====================

// Analiza los puertos y marca los sospechosos según criterios de seguridad
void analizarPuertosSospechosos(std::vector<PortInfo>& puertos, NivelSensibilidad sensibilidad);

// Función auxiliar para obtener descripción del nivel de sensibilidad
std::string obtenerDescripcionSensibilidad(NivelSensibilidad sensibilidad);

#endif // ANALISIS_H