#ifndef ESTRATEGIA_ESCANEO_H
#define ESTRATEGIA_ESCANEO_H

#include <string>
#include <vector>
#include "Escaneo.h"   // 👈 aquí para que sepa qué es PortInfo

// Contrato común para cualquier método de escaneo
class EstrategiaEscaneo {
public:
    virtual std::vector<PortInfo> escanear(
        const std::string& ip,
        const std::vector<int>& puertos,
        int timeoutMs = 500
    ) = 0;
    virtual ~EstrategiaEscaneo() = default;
};

#endif
