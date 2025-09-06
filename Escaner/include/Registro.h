#ifndef REGISTRO_H
#define REGISTRO_H

#include <string>
#include <vector>
#include "Analisis.h"   // Para AnalisisPuerto y PortInfo

// Guarda los resultados del escaneo en un archivo de texto
void guardarRegistro(const std::string& archivo,
                     const std::string& ip,
                     const std::vector<AnalisisPuerto>& analisis);

#endif // REGISTRO_H
