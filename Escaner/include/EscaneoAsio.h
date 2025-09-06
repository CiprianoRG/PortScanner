#ifndef ESCANEO_ASIO_H
#define ESCANEO_ASIO_H

#include "EstrategiaEscaneo.h"
// En EscaneoAsio.h
#include "Boost.Asio/asio.hpp"  // 👈 así sí lo encontrará
class EscaneoAsio : public EstrategiaEscaneo {
public:
    std::vector<PortInfo> escanear(
        const std::string& ip,
        const std::vector<int>& puertos,
        int timeoutMs = 500
    ) override;
};

#endif
