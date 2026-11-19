// External file (CSP forbids inline scripts).
window.ui = SwaggerUIBundle({
  url: "/api/openapi.yaml",
  dom_id: "#swagger-ui",
  deepLinking: true,
  persistAuthorization: false,
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
  layout: "StandaloneLayout",
});
