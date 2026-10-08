package com.example.tfgvpp.data.remote

data class VppEndpoints(
    val baseUrl: String,            // VPP, server-authenticated bootstrap (:8080)
    val raUrl: String,              // CA, registration authority side (:8081)
    val mtlsUrl: String,            // VPP, mutual TLS (:8443)
    val defaultApplianceUrl: String,// appliance emulated on the PC (:8082); a QR overrides it
    // The VPP as reached from the appliance, not from the phone.
    val vppUrlForAppliance: String,
    val vppMtlsUrlForAppliance: String,
)
