#include "Registro.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>

using namespace std;

// =====================
// Obtener fecha y hora actual
// =====================
string Registro::obtenerFechaHora() {
    time_t ahora = time(nullptr);
    tm* tiempoLocal = localtime(&ahora);
    
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tiempoLocal);
    return string(buffer);
}

// =====================
// Contar puertos abiertos
// =====================
int Registro::contarPuertosAbiertos(const vector<AnalisisPuerto>& resultados) {
    int count = 0;
    for (const auto& analisis : resultados) {
        if (analisis.info.estado == "Abierto") {
            count++;
        }
    }
    return count;
}

// =====================
// Guardar reporte completo en TXT
// =====================
void Registro::guardarReporteTXT(
    const vector<AnalisisPuerto>& resultados,
    const string& nombreArchivo,
    const string& ip,
    const string& metodoEscaneo
) {
    ofstream archivo(nombreArchivo);
    if (!archivo.is_open()) {
        cerr << "Error: No se pudo crear el archivo " << nombreArchivo << endl;
        return;
    }
    
    int totalPuertos = resultados.size();
    int puertosAbiertos = contarPuertosAbiertos(resultados);
    
    // ===================== ENCABEZADO =====================
    archivo << "==================================================\n";
    archivo << "               REPORTE DE ESCANEO\n";
    archivo << "==================================================\n";
    archivo << "Fecha y hora    : " << obtenerFechaHora() << "\n";
    archivo << "IP escaneada    : " << ip << "\n";
    archivo << "Método escaneo  : " << metodoEscaneo << "\n";
    archivo << "Total puertos   : " << totalPuertos << "\n";
    archivo << "Puertos abiertos: " << puertosAbiertos << "\n";
    archivo << "Tasa de apertura: " << fixed << setprecision(1) 
           << (puertosAbiertos * 100.0 / totalPuertos) << "%\n";
    archivo << "==================================================\n\n";
    
    // ===================== RESUMEN DE RIESGOS =====================
    int criticos = 0, altos = 0, medios = 0, bajos = 0;
    for (const auto& analisis : resultados) {
        if (analisis.info.estado == "Abierto") {
            switch (analisis.nivel_riesgo) {
                case RIESGO_CRITICO: criticos++; break;
                case RIESGO_ALTO: altos++; break;
                case RIESGO_MEDIO: medios++; break;
                case RIESGO_BAJO: bajos++; break;
                default: break;
            }
        }
    }
    
    archivo << "RESUMEN DE RIESGOS:\n";
    archivo << "--------------------------------------------------\n";
    archivo << "Críticos 🔴 : " << criticos << " puertos\n";
    archivo << "Altos    🟠 : " << altos << " puertos\n";
    archivo << "Medios   🟡 : " << medios << " puertos\n";
    archivo << "Bajos    🟢 : " << bajos << " puertos\n";
    archivo << "--------------------------------------------------\n\n";
    
    // ===================== DETALLE DE PUERTOS ABIERTOS =====================
    if (puertosAbiertos > 0) {
        archivo << "DETALLE DE PUERTOS ABIERTOS:\n";
        archivo << "==================================================\n";
        
        for (const auto& analisis : resultados) {
            if (analisis.info.estado == "Abierto") {
                archivo << "PUERTO: " << analisis.info.port << "\n";
                archivo << "  Servicio  : " << analisis.info.servicio << "\n";
                archivo << "  Protocolo : " << analisis.info.proto << "\n";
                archivo << "  Riesgo    : " << obtenerDescripcionRiesgo(analisis.nivel_riesgo) << "\n";
                archivo << "  Puntuación: " << analisis.puntuacion_riesgo << "/100\n";
                
                if (!analisis.vulnerabilidades.empty()) {
                    archivo << "  Vulnerabilidades:\n";
                    for (const auto& vuln : analisis.vulnerabilidades) {
                        archivo << "    * " << vuln << "\n";
                    }
                }
                
                if (analisis.info.sospechoso) {
                    archivo << "  ⚠️  SOSPECHOSO: " << analisis.info.razon << "\n";
                }
                
                archivo << "--------------------------------------------------\n";
            }
        }
    }
    
    // ===================== PUERTOS CERRADOS (solo lista) =====================
    archivo << "\nPUERTOS CERRADOS/FILTRADOS:\n";
    archivo << "==================================================\n";
    
    for (const auto& analisis : resultados) {
        if (analisis.info.estado != "Abierto") {
            archivo << "Puerto " << analisis.info.port << " : " << analisis.info.estado << "\n";
        }
    }
    
    // ===================== RECOMENDACIONES =====================
    archivo << "\n==================================================\n";
    archivo << "RECOMENDACIONES DE SEGURIDAD:\n";
    archivo << "==================================================\n";
    
    if (criticos > 0) {
        archivo << "🚨 ALERTA CRÍTICA: " << criticos << " puertos con riesgo CRÍTICO\n";
        archivo << "   * Cerrar inmediatamente estos puertos\n";
        archivo << "   * Investigar posibles compromisos\n";
        archivo << "   * Revisar logs del sistema\n\n";
    }
    
    if (altos > 0) {
        archivo << "⚠️  PRECAUCIÓN: " << altos << " puertos con riesgo ALTO\n";
        archivo << "   * Fortificar servicios (ej: cambiar credenciales SSH)\n";
        archivo << "   * Implementar firewalls de aplicación\n";
        archivo << "   * Monitorear acceso a estos puertos\n\n";
    }
    
    if (puertosAbiertos == 0) {
        archivo << "✅ ESTADO ÓPTIMO: No se encontraron puertos abiertos\n";
    } else if (criticos == 0 && altos == 0) {
        archivo << "✅ ESTADO ACEPTABLE: Solo puertos de bajo riesgo abiertos\n";
    }
    
    archivo << "==================================================\n";

    archivo.close();
}