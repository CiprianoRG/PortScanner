#ifndef ESCANEO_NMAP_H
#define ESCANEO_NMAP_H

#include "EstrategiaEscaneo.h"
#include <string>
#include <vector>

// Implementación de escaneo usando Nmap
class EscaneoNmap : public EstrategiaEscaneo {
public:
    std::vector<PortInfo> escanear(
        const std::string& ip,
        const std::vector<int>& puertos,
        int timeoutMs = 500
    ) override;
};

#endif // ESCANEO_NMAP_H
