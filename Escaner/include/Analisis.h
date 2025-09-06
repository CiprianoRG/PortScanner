#ifndef ANALISIS_H
#define ANALISIS_H

#include <vector>
#include "EstrategiaEscaneo.h"  // Para PortInfo

// =====================
// Niveles de riesgo automáticos (NO de sensibilidad de escaneo)
// =====================
enum NivelRiesgo {
    RIESGO_CRITICO = 0,    // Puerto críticamente peligroso
    RIESGO_ALTO = 1,       // Puerto de alto riesgo  
    RIESGO_MEDIO = 2,      // Puerto de riesgo medio
    RIESGO_BAJO = 3,       // Puerto de bajo riesgo
    RIESGO_DESCONOCIDO = 4 // Riesgo indeterminado
};

// =====================
// Nueva estructura para análisis detallado
// =====================
struct AnalisisPuerto {
    PortInfo info;              // Información del puerto
    NivelRiesgo nivel_riesgo;   // Nivel de riesgo calculado
    int puntuacion_riesgo;      // Puntuación numérica (0-100)
    std::vector<std::string> vulnerabilidades; // Vulnerabilidades detectadas
};

// =====================
// Funciones de análisis automático
// =====================

// Analiza y asigna nivel de riesgo automáticamente a cada puerto
void analizarRiesgoPuertos(std::vector<AnalisisPuerto>& resultados);

// Función principal que reemplaza la anterior
std::vector<AnalisisPuerto> analizarPuertosDetallado(const std::vector<PortInfo>& puertos);

// Obtener descripción del nivel de riesgo
std::string obtenerDescripcionRiesgo(NivelRiesgo nivel);

// Calcular puntuación de riesgo (0-100)
int calcularPuntuacionRiesgo(int puerto, const std::string& servicio);

#endif // ANALISIS_H