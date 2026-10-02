# PDF Inspector & Signature Verifier

> Trabajo Fin de Máster · Servicio web para la auditoría técnica y forense de documentos PDF.
>
> **Estado:** completo y desplegado en <https://vps-651608c6.vps.ovh.net/> (§4); diapositivas de la presentación en §9. Este README es un documento vivo: se actualiza con cada cambio. Desde T14 las anclas de confianza se generan desde las Listas de Confianza oficiales de la UE (§2.7, §4).

## Índice

1. [Descripción general](#1-descripción-general)
2. [Cómo funciona](#2-cómo-funciona)
3. [Stack tecnológico](#3-stack-tecnológico)
4. [Instalación y ejecución](#4-instalación-y-ejecución)
5. [Estructura del proyecto](#5-estructura-del-proyecto)
6. [Funcionalidades principales](#6-funcionalidades-principales)
7. [Tests y calidad](#7-tests-y-calidad)
8. [Usuario y contraseña de prueba](#8-usuario-y-contraseña-de-prueba)
9. [Presentación](#9-presentación)
10. [Decisiones técnicas](#10-decisiones-técnicas)
11. [Historial de cambios](#11-historial-de-cambios)
12. [Repositorio y licencia](#12-repositorio-y-licencia)
13. [Componentes de terceros](#13-componentes-de-terceros)

---

## 1. Descripción general

**PDF Inspector & Signature Verifier** es un servicio web monolítico modular que analiza un documento PDF en un único ciclo de procesamiento y devuelve un informe JSON estructurado con:

- **Integridad criptográfica de las firmas digitales** (PAdES / CMS-PKCS#7): si la firma es matemáticamente válida y si el documento ha sido modificado después de firmarse.
- **Sellos de tiempo** (RFC 3161) y **cadena de confianza X.509** del firmante.
- **Revocación** (OCSP / CRL) como comprobación opcional y acotada.
- **Conformidad PDF/A-1b** mediante el módulo oficial *preflight* de Apache PDFBox.
- **Propiedades físicas**: versión, número de páginas, rotación y dimensiones por página, cifrado y permisos.
- **Veredicto general por firma** (✅/⚠️/❌) que resume integridad + cadena + revocación en una sola conclusión, con sus motivos explícitos (§2.10).

**Demo en línea:** <https://vps-651608c6.vps.ovh.net/> (HTTPS, sin login; sube PDFs de hasta 80 MB).

El servicio no guarda los documentos analizados: es **sin estado** y sin base de datos. Además de la API REST/Swagger UI, incluye una interfaz web estática con dos pantallas, «Validar» (§2.14) y «Firmar» (§2.15), sin frameworks ni dependencias externas.

## 2. Cómo funciona

### 2.1 Flujo de análisis

```
Cliente (interfaz web "Validar" o Swagger UI)
   │  POST /api/v1/pdf/analyze  (multipart, PDF ≤ 80 MB)
   ▼
api ──► application: AnalyzePdfUseCase
            │ orquesta los puertos del dominio (ver §2.11)
            ├─► HashCalculator            SHA-256 / SHA-512
            ├─► PdfDocumentReader         estructura, páginas, permisos, XMP
            ├─► SignatureVerifier         /ByteRange + CMS + RFC 3161
            ├─► CertificateChainValidator PKIX contra trust store
            ├─► RevocationChecker         OCSP/CRL (opcional, toda la ruta, plazo total 6 s)
            ├─► PdfaConformanceValidator  preflight PDF/A-1b
            └─► SignatureVerdictPolicy    veredicto por firma + global (§2.10)
   ◄── PdfAnalysisReportDto (JSON) / ProblemDetail (error)
```

**En palabras sencillas.** Quien usa el servicio (desde la página web o desde Swagger UI) sube un PDF. El servicio lo pasa por una serie de comprobaciones, una detrás de otra, y responde con un único informe:

1. **Recepción.** Un *controlador* REST recibe el fichero (capa `api`). Si algo falla, responde con un error estándar (`ProblemDetail`) que explica la causa.
2. **Orquestación.** Un único caso de uso, `AnalyzePdfUseCase`, decide el orden de las comprobaciones: calcula los hashes, lee la estructura del PDF, verifica cada firma, valida la cadena de confianza, consulta la revocación si se pidió y comprueba el formato PDF/A. Si una comprobación falla, las demás siguen adelante y el informe indica qué sección falló.
3. **Veredicto.** Con todos esos resultados, una política pura (`SignatureVerdictPolicy`) decide, firma por firma, si el documento es válido, no admitido o no válido, y por qué (§2.10).
4. **Respuesta.** Un *mapeador* convierte el resultado interno en un JSON pensado para el cliente (los DTOs), sin exponer las clases internas del dominio.

Spring conecta todas las piezas al arrancar la aplicación (§2.13). La página web «Validar» usa este mismo servicio (§2.14). La pantalla «Firmar» no lo usa para firmar: firma en el equipo del usuario con AutoFirma (§2.15).

**Cómo sabemos que funciona.** El caso de uso se prueba de tres maneras: tests unitarios de cada pieza, un test de integración con los componentes reales (PDFBox y Bouncy Castle) y un test completo que sube un PDF por HTTP y comprueba la respuesta. Además, las reglas de ArchUnit vigilan en cada compilación que cada capa solo dependa de la que debe (§2.11, §2.12).

### 2.2 Modelo de dominio y puertos

El núcleo del sistema (`domain/`) es Java puro: no importa Spring, PDFBox ni Bouncy Castle. Todo el informe se modela con **records inmutables** que validan sus datos al construirse y copian las listas que reciben, para que nadie pueda modificarlas desde fuera. Los *puertos* son las interfaces por las que el dominio pide trabajo a la infraestructura.

| Concepto | Tipo | Regla que aplica |
|---|---|---|
| Informe completo | `PdfAnalysisReport` | Agrupa hashes, estructura, seguridad, PDF/A y firmas |
| Hashes | `DocumentHashes` | SHA-256 (64 hex) y SHA-512 (128 hex), en minúsculas |
| Página | `PageInfo`, `Box` | MediaBox/CropBox con ancho y alto calculados |
| Rotación | `Rotation` | Normaliza a 0/90/180/270 (`-90 → 270`, `450 → 90`); un valor que no sea múltiplo de 90 es inválido |
| Orientación | `Orientation` | Se calcula **después** de rotar: a 90° o 270° se intercambian ancho y alto |
| Cobertura de firma | `ByteRangeCoverage` | 4 valores, empieza en 0, tramos sin solaparse; indica si cubre todo el fichero |
| Estado de integridad | `IntegrityStatus` | `INTACT`, `MODIFIED_AFTER_SIGNING`, `INVALID_SIGNATURE`, `UNSUPPORTED` |
| Certificado | `CertificateInfo` | Sujeto, `commonName`, emisor, fechas, algoritmo, URLs OCSP/CRL y el certificado codificado (DER) |
| Sello de tiempo | `TimestampInfo` | `genTime`, `tsaName`, `imprintValid`, `signatureValid`, certificado y cadena de la TSA (`tsaChain`), si declara `id-kp-timeStamping`, una nota opcional y `trusted` (si puede fijar el momento de validación, §2.6); `absent()` cuando no hay sello |
| Cadena y revocación | `ChainStatus`, `RevocationStatus` | Empiezan como `NOT_CHECKED`; el caso de uso los completa con `withChainAndRevocation(...)` |
| Error de sección | `SectionError`, `AnalysisSection` | Si una sección guardada (`PDFA`, `SIGNATURES`) falla de forma inesperada, `PdfAnalysisReport.sectionErrors()` lo informa, para que una lista de firmas vacía por ese motivo nunca se confunda con "este documento no tiene firmas" |
| Veredicto por firma | `SignatureVerdict` (`SignatureReport.verdict()`/`verdictReasons()`) | `VALID`/`NOT_ADMITTED`/`INVALID`, calculado por `domain/policy/SignatureVerdictPolicy` (§2.10) |
| Veredicto del documento | `OverallVerdict` (`PdfAnalysisReport.overallVerdict()`) | El peor veredicto entre todas las firmas; método calculado, no un componente almacenado del record |

Los puertos son `HashCalculator`, `PdfDocumentReader`, `SignatureVerifier`, `CertificateChainValidator`, `RevocationChecker` y `PdfaConformanceValidator`. El verificador de firmas devuelve cada `SignatureReport` con cadena y revocación sin comprobar; después, el caso de uso las completa. Así cada adaptador tiene una sola responsabilidad y la revocación puede omitirse sin tocar el verificador.

### 2.3 Estructura, seguridad y declaración PDF/A

Esta parte lee las propiedades "físicas" del PDF: qué versión es, cuántas páginas tiene, cómo están giradas, si está cifrado y qué permisos concede. `infrastructure/pdfbox/PdfBoxDocumentReader` implementa el puerto `PdfDocumentReader` sobre PDFBox 3 y `xmpbox`, sin dejar escapar ningún tipo de esas librerías fuera del adaptador.

- **Versión**: la de cabecera se extrae de los primeros bytes (`%PDF-x.y`); la del catálogo, con `PDDocumentCatalog#getVersion()` (puede ser `null`). Si no hay cabecera `%PDF-` en los primeros 1024 bytes pero PDFBox consigue parsear el fichero, `headerVersion` se informa como `null` ("desconocida") en vez de abortar.
- **Rotación por página**: se lee el atributo `/Rotate` sin normalizar (heredado del nodo `/Pages` si hace falta). Solo un entero, o un real sin parte decimal (`90.0`), es válido; un valor no múltiplo de 90, un real no entero (`90.5`) o un valor no numérico se marca inválido sin truncarlo (`rawRotation`, `rotationValid()`), la orientación se calcula como si fuera `0°` y el análisis continúa.
- **MediaBox / CropBox y orientación**: `PDPage#getMediaBox()`/`getCropBox()` (la CropBox hereda de la MediaBox si no está declarada); la orientación se calcula tras aplicar la rotación efectiva.
- **Número de revisiones**: `RevisionCounter` recorre la cadena de referencias cruzadas (`xref`/`trailer`) siguiendo los enlaces `/Prev` desde el último `startxref`, y cuenta una revisión por sección visitada (no por marcador `%%EOF`, que sobrestima los PDF *linealizados*). Detecta `/Linearized` para no contar esa sección extra, protege contra bucles con un conjunto de posiciones visitadas y vuelve al conteo por `%%EOF` si no hay cadena de xref o el `startxref` cae fuera del fichero. Localiza cada palabra clave una sola vez y salta con búsqueda binaria (coste `O(n log n)`), y no guarda estado compartido, así que es seguro con peticiones concurrentes. **Límites (T20)**: guarda las posiciones en *arrays* primitivos y, si alguna palabra clave (`stream`, `startxref`, `/Prev`) aparece más de `max-revision-markers` veces (por defecto 1 000 000; un fichero hostil de 80 MB podía generar millones de posiciones y cientos de MB de basura temporal), abandona el análisis y devuelve `revisionCount = 1` con `revisionCountLowerBound = true` («al menos»); lo mismo ocurre si la cadena supera `max-revisions` secciones (10 000), y entonces `revisionCount` es el tope alcanzado. Nunca falla ni devuelve un error: la respuesta sigue siendo `200`.
- **Páginas (T20)**: el detalle por página (`pages`) se limita a las primeras `max-pages` páginas (por defecto 1 000); `pageCount` sigue siendo el total real y `pagesTruncated = true` indica que la lista está recortada (la interfaz avisa «Se muestran solo las primeras N páginas de M»). Un árbol de páginas hostil ya no construye una lista ni un JSON de tamaño ilimitado.
- **Cifrado y permisos**: `PDDocument#isEncrypted()` más `AccessPermission`, mapeado a los ocho valores de `Permission`. Un documento sin contraseña de usuario (o con contraseña vacía) se abre y se informan sus restricciones; con contraseña de usuario no vacía no puede abrirse y lanza `EncryptedPdfException`.
- **Declaración PDF/A (XMP)**: se exportan los metadatos XMP del catálogo y se parsean con `DomXmpParser`, extrayendo `pdfaid:part`/`pdfaid:conformance`. Sin XMP, sin ese esquema o con XMP corrupto se informa `PdfaDeclaration.NONE`. Es solo la *declaración*; la validación formal está en §2.9.
- Un fichero que PDFBox no pueda parsear lanza `InvalidPdfException`.

`infrastructure/crypto/JcaHashCalculator` implementa `HashCalculator` con `java.security.MessageDigest` (SHA-256/SHA-512), sin depender de PDFBox ni Bouncy Castle.

### 2.4 Firmas e integridad (`/ByteRange`)

Esta es la comprobación central del servicio: decidir si una firma es auténtica y si el documento cambió después de firmarse. `infrastructure/bouncycastle/BcSignatureVerifier` implementa el puerto `SignatureVerifier` con PDFBox 3 (para leer los diccionarios de firma) y Bouncy Castle 1.86 (para el CMS). Recorre **cada** campo de firma y evalúa cada uno de forma **independiente**.

Una firma PDF no firma el fichero entero, sino los bytes indicados en el array **`/ByteRange`** `[a b c d]`: dos tramos firmados que dejan un hueco en medio donde va la propia firma (`/Contents`, un contenedor CMS en hexadecimal). La verificación comprueba, en este orden:

1. **Estructura del `/ByteRange`.** Además de la validación del dominio (`ByteRangeCoverage`: empieza en 0, tramos sin solaparse, dentro del fichero), se comprueba a nivel de bytes que el hueco está delimitado por `<`/`>` y que su longitud coincide con el tamaño hexadecimal de `/Contents`, leído de forma independiente por PDFBox (`PDSignature#getContents()`) y no derivado del propio `/ByteRange`. Un `/ByteRange` hostil o inconsistente nunca lanza una excepción: esa firma se informa como `INVALID_SIGNATURE` sin abortar las demás.
2. **Integridad matemática (CMS).** Se lee `/Contents` como un único objeto ASN.1 (PDFBox rellena el hueco reservado con ceros, y `CMSSignedData` rechaza los bytes sobrantes) y se verifica con Bouncy Castle (`SignerInformation#verify(...)`): comprueba que el `messageDigest` firmado coincide con el resumen de los bytes cubiertos y que la firma es válida para la clave del firmante. Si un solo byte firmado cambia, el resultado es **`INVALID_SIGNATURE`**.
3. **Cobertura del fichero.** Si el final del segundo tramo (`c + d`) alcanza el tamaño del fichero, la firma es **`INTACT`**. Si es menor, hay bytes añadidos **después** de firmar (una *actualización incremental*): la firma sigue siendo válida para su revisión, pero el resultado es **`MODIFIED_AFTER_SIGNING`**.

**Varias firmas.** Con un documento firmado dos veces, la **primera** firma queda como `MODIFIED_AFTER_SIGNING` (la segunda firma es una actualización incremental posterior) y solo la **última**, cuyo `/ByteRange` llega al final real, es `INTACT`. Es el comportamiento esperado de PDF; cómo se traduce en veredicto se explica en §2.10.

**Subfiltros soportados.** `adbe.pkcs7.detached` y `ETSI.CAdES.detached` se verifican por completo. `adbe.pkcs7.sha1`, `adbe.x509.rsa_sha1` y cualquier subfiltro desconocido se informan como **`UNSUPPORTED`**. `ETSI.RFC3161` (sello de tiempo de *documento*) se mantiene deliberadamente `UNSUPPORTED` (§10).

**Robustez.** Todo el ciclo por campo (lectura + evaluación) está bajo la misma protección, así que un campo hostil no aborta el análisis de los demás. Si el CMS verifica pero un certificado no puede volver a codificarse a DER (un fallo de mapeo, no de criptografía), se mantiene el `IntegrityStatus` real con la cadena parcial y una nota de anomalía (`SignatureReport#anomaly`).

**Integridad de la firma frente a validez del certificado.** Son dos hechos independientes:

- La firma se verifica siempre con la **clave pública** del firmante, no con el certificado completo. Así Bouncy Castle no rechaza una firma íntegra solo porque el certificado hubiera caducado en el instante de firma. Esa vigencia se comprueba por separado y, si no se cumplía, se añade una nota de anomalía sin invalidar la integridad; la confianza y vigencia de la cadena las decide `PkixCertificateChainValidator` (§2.7).
- Algunas herramientas reales codifican el `digestAlgorithm` del `SignerInfo` con el OID de un algoritmo de **firma** (p. ej. `sha256WithRSAEncryption`) en lugar del de **resumen** (`id-sha256`). Cuando es un OID de firma inequívoco (tabla en `DigestAlgorithmOidNormalizer`: RSA PKCS#1 v1.5, ECDSA y `id-dsa-with-sha1`; sin `id-RSASSA-PSS` ni `rsaEncryption` a secas), la verificación construye el `ContentVerifier` directamente con ese OID en lugar de pasar por la reconstrucción interna de Bouncy Castle, que solo corrige la variante SHA-1. Se añade la nota de anomalía *"non-standard digestAlgorithm encoding"* sin invalidar la firma, y una manipulación posterior sigue dando `INVALID_SIGNATURE`.
- La cadena de certificados se extrae y se informa siempre que el CMS se pudo parsear, aunque la verificación criptográfica falle.
- `INVALID_SIGNATURE` y `UNSUPPORTED` siempre llevan un motivo legible (`anomaly`), con texto fijo y no sensible (*"messageDigest does not match the signed bytes"*, *"CMS container could not be parsed"*, ...). El detalle real de una excepción inesperada se registra por log (`System.Logger`) y nunca llega al cliente.

**Límite de campos de firma (T20).** `BcSignatureVerifier` recorre el árbol de campos del formulario de forma perezosa y analiza como mucho `max-signature-fields` campos con firma (50). Los siguientes solo se cuentan (`SignatureExtraction.skippedFields`); como la firma decisiva podría esconderse tras el límite, el caso de uso añade un `SectionError` de la sección `SIGNATURES` («N signature field(s) were not analysed…») y el veredicto del documento pasa a `ANALYSIS_INCOMPLETE`, **nunca** `VALID`. Las firmas no analizadas tampoco pueden hacer de «firma posterior» que exima a una anterior modificada (§2.10): no están en la lista.

### 2.5 Extracción de certificados

Para saber quién firmó hace falta extraer del CMS el certificado del firmante y los de su cadena. Para cada firma con CMS verificable, `BcSignatureVerifier` obtiene el certificado del firmante y todos los incluidos (normalmente firmante + emisor) y los mapea a `CertificateInfo`: sujeto y emisor, número de serie en hexadecimal, fechas de validez, algoritmo, certificado en DER. La cadena se ordena **firmante primero**, siguiendo el emisor de cada certificado hasta una raíz autofirmada o hasta que el siguiente emisor no esté en el propio CMS.

- **Límites (T20).** De un mismo CMS se toman como máximo `max-certificates-per-signature` certificados (50): primero el del firmante y luego el resto en el orden del contenedor; si hay más, se descartan (una cadena que así quede incompleta solo puede acabar en `NOT_ADMITTED`, nunca en confianza) y `anomaly` lo dice («signature carries N certificates; only M were considered…»). La ordenación firmante → raíz sigue los emisores como mucho `max-chain-length` certificados (10), de modo que el coste ya no crece de forma cuadrática con un CMS lleno de certificados.
- **Nombres legibles.** Sujeto y emisor se formatean con Bouncy Castle (`X500Name` + `BCStyle`), no con el RFC 2253 de la JDK, que vuelca atributos que no conoce (p. ej. `emailAddress`) como `#16<hex>`. El `commonName` se extrae aparte del atributo `CN` (sin escapes RFC 2253, también con RDN multivalor) y vive en el dominio porque `api` no puede depender de `infrastructure`.
- **URLs de revocación.** De cada certificado se leen las extensiones *Authority Information Access* (OCSP) y *CRL Distribution Points*. Una extensión ausente o mal formada no invalida el certificado: se informa sin URLs.

### 2.6 Sellos de tiempo RFC 3161

Un sello de tiempo demuestra, con la firma de un tercero de confianza, **cuándo** existía una firma. Es un atributo CMS *no firmado* (`id-aa-signatureTimeStampToken`, OID `1.2.840.113549.1.9.16.2.14`) que una TSA (*Time-Stamping Authority*) añade a una firma ya existente; sella el **valor de la firma**, no el documento, así que puede añadirse después sin invalidar nada.

La fecha de firma que declara el propio firmante (`/M`, atributo `signingTime`) no ofrece ninguna garantía externa: quien tenga la clave puede escribir cualquier fecha. `claimedSigningTime` se sigue informando, pero **solo como dato informativo**; nunca se usa para validar (§2.7). `TimestampInfo.genTime()` es la fecha de la TSA, y solo vale como prueba cuando el sello es **de confianza** (más abajo).

`infrastructure/bouncycastle/SignatureTimestampVerifier` (Bouncy Castle `org.bouncycastle.tsp`) verifica dos cosas independientes y **informa** de dos hechos más; no decide la confianza:

1. **Imprint del mensaje.** Se recalcula el resumen de los bytes de la firma con el algoritmo que declara el propio sello y se compara con el `messageImprint`. Si no coincide, el sello es inválido (`imprintValid=false`), pero **la integridad de la firma que lo contiene no se ve afectada**.
2. **Firma de la TSA.** El CMS del sello se verifica contra el certificado de la TSA (`TimeStampToken#validate(...)`). Esto **no** prueba que la TSA sea legítima: cualquiera puede fabricar una TSA con su propia raíz y escribir la fecha que quiera.
3. **Uso extendido y cadena de la TSA (se informan, no se deciden aquí).** `TimestampInfo#tsaTimeStampingEku` indica si el certificado de la TSA declara `id-kp-timeStamping`, y `TimestampInfo#tsaChain` es el certificado de la TSA seguido de sus emisores presentes en el sello (solo los eslabones encadenados por emisor/sujeto, para que un certificado ajeno embebido no decida la confianza). El adaptador nunca marca `trusted`.

**Dónde se busca el certificado de la TSA (T26a).** Un sello pedido con `certReq=false` (RFC 3161 §2.4.1) no lleva ningún certificado. `TsaCertificateLocator` busca entonces el de la TSA, por este orden: (1) en el propio sello; (2) entre los certificados del CMS de la firma; (3) entre los anclas de confianza configurados, que llegan por el puerto de dominio `TrustedCertificateSource` (lo implementa `TrustAnchorProvider`; así el adaptador de Bouncy Castle no depende del adaptador PKI). Un candidato solo se acepta si coincide con el identificador del firmante del sello (`TimeStampToken#getSID()`: emisor y número de serie, o identificador de clave del sujeto) **y** con el hash `ESSCertID`/`ESSCertIDv2` que la propia TSA firmó en el sello (RFC 5035); así no se puede sustituir por otro certificado, ni siquiera por uno con el mismo emisor y serie pero distinto contenido. Encontrarlo no lo hace de confianza: la cadena sigue validándose como abajo, y los emisores de la TSA también se buscan en el CMS y en los anclas. Si no aparece en ningún sitio se conserva el comportamiento anterior (nota *"TSA certificate not found in the timestamp token"*, sello no de confianza).

**Sello de tiempo de confianza (T19).** La decisión la toma `AnalyzePdfUseCase` (§2.11), porque necesita los anclas de confianza a través del puerto `CertificateChainValidator`. Un sello es `trusted` solo si se cumplen **todas** estas condiciones:

- `imprintValid` y `signatureValid`;
- el certificado de la TSA declara `id-kp-timeStamping` (obligatorio). La RFC 3161 §2.3 pide además que sea el único uso y que esté marcado como crítico; **no se exige**, porque la seguridad la aporta la cadena de confianza y varias TSA reales omiten el bit de criticidad;
- la cadena de la TSA es `TRUSTED` en el `genTime` del sello, validada con el mismo `PkixCertificateChainValidator` y los mismos anclas que los firmantes (§2.7);
- el `genTime` no es posterior a «ahora» (reloj inyectado) más 5 minutos de tolerancia.

Un sello que no cumple alguna se sigue informando en el JSON (`genTime`, TSA, `note` empezando por `TSA not trusted: …` con el motivo), pero **nunca influye en el momento de validación**. **Limitación:** no se comprueba la revocación del certificado de la TSA.

Casos límite, ninguno lanza una excepción: sin sello → `TimestampInfo.absent()`; sello con bytes corruptos → inválido con nota; certificado de la TSA no mapeable a `CertificateInfo` → se conservan `genTime`, `imprintValid` y `signatureValid` y se añade una nota. Las notas son textos fijos (*"Malformed RFC 3161 timestamp token"*, *"TSA signature verification failed"*, *"TSA certificate data could not be mapped"*): el mensaje de Bouncy Castle o de la excepción va solo al log del servidor (T23); un fallo inesperado al validar la cadena de la TSA → sello no de confianza (la firma no se pierde).

### 2.7 Cadena de confianza X.509 (PKIX)

Aquí se responde a "¿el certificado del firmante llega a una autoridad en la que confiamos?". `infrastructure/pki/PkixCertificateChainValidator` implementa `CertificateChainValidator` con la implementación PKIX de la JDK (`CertPathBuilder` + `PKIXBuilderParameters`), sin depender de Bouncy Castle.

- **Momento de validación.** `validate(chain, validationTime)` comprueba vigencia y confianza en un instante que decide el caso de uso (§2.11): el `genTime` de un sello RFC 3161 **de confianza** (§2.6) y, en cualquier otro caso, el instante actual. La fecha que declara el firmante no se usa nunca. Consecuencia aceptada: una firma sin sello de confianza cuyo certificado ya caducó queda `NOT_ADMITTED` (`CHAIN_EXPIRED`).
- **Revocación desactivada aquí** (`setRevocationEnabled(false)`): se aplica por separado (§2.8), una vez la cadena ya es de confianza.
- **Estados** (`ChainStatus`): `TRUSTED` (la ruta se construye), `UNTRUSTED_ROOT` (llega a un autofirmado que no está en el almacén), `INCOMPLETE_CHAIN` (falta un emisor), `EXPIRED` (algún certificado está fuera de vigencia en `validationTime`; comprobación previa e independiente de PKIX), `NOT_CHECKED` (lista vacía). Como el `CertPathBuilder` no distingue de forma estable `UNTRUSTED_ROOT` de `INCOMPLETE_CHAIN`, se aplica una comprobación propia: si la cadena presentada es estructuralmente completa (cada certificado verifica contra el siguiente hasta un autofirmado) el problema es la raíz; si no, falta un eslabón. Un certificado que no puede reparsearse desde su DER se informa como `INCOMPLETE_CHAIN`.
- **Ruta validada.** `validatedPath` devuelve los certificados que PKIX realmente usó (incluido el ancla si no venía en el CMS); la revocación usa esa ruta y no la cadena presentada (§2.8).
- **Almacén de confianza** (`TrustAnchorProvider`): combina las anclas empaquetadas en `src/main/resources/truststore/` (los ficheros que enumera `truststore/index.txt`) con, opcionalmente, un directorio externo de certificados y/o un fichero PKCS#12 (propiedades `pdfvalidator.truststore.*`, §4). Un fichero inválido del directorio externo se omite sin abortar la carga.
- **Origen de las anclas: la Lista de Confianza española, verificada a través de la LOTL de la UE (T14).** El servidor nunca descarga nada en ejecución: las anclas se generan **fuera** de él con una herramienta de mantenimiento (`TslSync`, §4) que una tarea semanal de GitHub Actions ejecuta y propone como *pull request* (§10).

**Anclas de confianza empaquetadas** (`src/main/resources/truststore/`; generadas, no se editan a mano). La herramienta descarga la LOTL de la UE y la Lista de Confianza española (TSL), verifica la firma XML de ambas y escribe un fichero `.crt` (certificado en PEM) por ancla, con nombre `<tsp>__<servicio>__<prefijo-sha256>.crt`, más `index.txt` y `SOURCES.md` (URLs, números de secuencia, fechas de emisión y `NextUpdate`, huellas SHA-256 de los firmantes de las listas, reglas de selección y una tabla con cada ancla: TSP, servicio, tipo, fecha de inicio del estado, sujeto, SHA-256 y fin de vigencia). Solo cuenta el estado **actual** de cada servicio (`ServiceInformation/ServiceStatus`; el historial `ServiceHistory` se ignora), y entran los certificados `X509Certificate` de:

- servicios `CA/QC` en estado `granted` que emiten certificados **para firma electrónica**: con `AdditionalServiceInformation` `…/SvcInfoExt/ForeSignatures`, con el calificador `…/SvcInfoExt/QCForESig`, o **sin ninguna restricción de uso** (ni `ForeSignatures`, ni `ForeSeals`, ni `ForWebSiteAuthentication`). Los servicios solo para sellos electrónicos o solo para autenticación de sitios web quedan fuera;
- servicios `TSA/QTST` (sellos de tiempo cualificados) en estado `granted`;
- siempre que el certificado no haya caducado ya cuando se genera el almacén (`notAfter` futuro). Un certificado que aparece en varios servicios se empaqueta una sola vez (por SHA-256).

Generación del 2026-10-02 (LOTL n.º 395, TSL española n.º 189): **145 anclas**, 77 `CA/QC` y 68 `TSA/QTST`. Sustituyen a las 9 anclas curadas a mano que había antes (5 raíces de CCADB y 4 CA emisoras extraídas de la TSL). Qué pasa con aquellas:

| Ancla anterior | Situación con el almacén generado |
|---|---|
| AC RAIZ FNMT-RCM, ACCVRAIZ1, Firmaprofesional CIF A62634068, Izenpe.com (raíces) | Las raíces no se publican en la TSL; entran sus **CA emisoras** cualificadas para firma (p. ej. AC FNMT Usuarios, AC Representación, AC Sector Público y sus versiones G2; ACCVCA-120, ACCV RSA1/ECC1; las CA de Firmaprofesional e Izenpe) y sus TSA |
| AC RAIZ FNMT-RCM SERVIDORES SEGUROS (raíz TLS) | Fuera: no emite certificados de firma |
| AC RAIZ DNIE 2 | Dentro (la TSL la publica como servicio `CA/QC`), junto con AC DGP 004 |
| AC FNMT Usuarios | Dentro |
| AC CAMERFIRMA FOR LEGAL PERSONS - 2016 | **Fuera**: la TSL la limita a sellos electrónicos (`ForeSeals`); sí entran otras CA de Camerfirma para firma (p. ej. AC CAMERFIRMA FOR NATURAL PERSONS - 2016) |
| AC Componentes Informáticos (FNMT) | **Fuera**: la TSL la limita a sellos y autenticación web (`ForeSeals`, `ForWebSiteAuthentication`) |

**Las anclas no son raíces autofirmadas.** El modelo eIDAS publica la CA **emisora** cualificada (y el certificado de la unidad TSA) como servicio de confianza, no su raíz. El `CertPathBuilder` de la JDK resuelve una ruta en cuanto alcanza *cualquier* certificado configurado como ancla, aunque no sea autofirmado, y acepta como ruta vacía un certificado que es él mismo un ancla (el de una TSA publicada en la TSL). Esto resuelve también el caso real de los PDF firmados con FNMT, cuyo CMS solo trae el certificado del firmante: el ancla es directamente la CA emisora.

**Cómo añadir raíces propias:** sin tocar el código, con un directorio externo (un certificado por fichero, PEM o DER) y/o un PKCS#12; se combinan con las empaquetadas, nunca las sustituyen. Es también la vía para confiar en una CA que la regla anterior deja fuera (por ejemplo, una CA solo de sellos).

### 2.8 Revocación OCSP/CRL

La revocación responde a "¿el emisor ha anulado este certificado?". Es una función **opcional, acotada y de mejor esfuerzo**: se activa con `checkRevocation=true`, nunca bloquea el resto del análisis y, si algo falla, el resultado es `UNKNOWN`. `infrastructure/revocation/CompositeRevocationChecker` implementa `RevocationChecker`: OCSP primero, CRL como respaldo.

**Orden y semántica:**

1. Sin URL OCSP ni CRL (extensiones AIA/CDP) o sin emisor → `UNKNOWN`.
2. Se prueba OCSP con cada URL declarada (sin repetidas y como mucho 3), en orden, hasta un resultado concluyente (`GOOD`/`REVOKED`).
3. Si OCSP no fue concluyente y hay URL CRL, se prueba CRL igual (mismas reglas).
4. Si ninguno fue concluyente → `UNKNOWN` con un motivo que combina ambos intentos.
5. Cualquier fallo de red, protocolo o criptografía se traduce a `UNKNOWN` con un motivo estable y no sensible (el detalle se registra por log, solo el nombre de la clase de la excepción).

**Toda la ruta, no solo el firmante (T21).** Se comprueba cada certificado de la ruta validada (§2.7) **excepto el ancla de confianza**, cada uno frente a su emisor: el firmante y las CA intermedias. Antes solo se miraba el firmante, así que una intermedia revocada con el firmante todavía `GOOD` daba `VALID`. El resultado se agrega así: cualquier `REVOKED` → `REVOKED` (la política de veredicto lo lleva a `INVALID`; la comprobación se detiene en el primero); si no, cualquier `UNKNOWN` o resultado no concluyente → `UNKNOWN` (`NOT_ADMITTED`, *fail-closed* como antes); solo si **todos** son `GOOD` el resultado es `GOOD`. El texto de detalle del firmante no cambia; el de una CA lleva el prefijo `CA certificate '<sujeto>': …` para saber qué certificado provoca el resultado. El ancla no se comprueba: no hay nadie por encima que pueda revocarla y su confianza es una decisión de configuración local (§2.7). Consecuencia deliberada: una CA intermedia sin URL OCSP/CDP deja el resultado en `UNKNOWN`.

**Presupuesto acotado (T21).** Un certificado hostil o mal emitido no puede provocar esperas ni tráfico saliente arbitrarios:

- Las URLs de cada certificado se deduplican y se limitan a **3 por método** (OCSP y CRL).
- Cada petición (resolución DNS + conexión + respuesta) tiene un tope de **2 s**, y además toda la comprobación de revocación de una firma —OCSP y CRL de todos los certificados de la ruta— comparte **un único plazo de 6 s** (`Deadline`). Agotado, no se hace ningún intento más y el resultado es `UNKNOWN` con el motivo *revocation time budget exhausted*.
- La resolución DNS corre **bajo ese plazo**: se ejecuta en un grupo acotado de 16 hilos demonio y, si el DNS no responde a tiempo, la URL se rechaza (*host could not be resolved within the time limit*); si el grupo está saturado por consultas atascadas, se rechaza en vez de encolar. Se sigue resolviendo **una sola vez** y conectando a esa dirección (arriba).
- Las respuestas HTTP tienen tope de tamaño (10 MB de cuerpo) y también de **cabeceras**: línea de estado, cabecera, tamaño de fragmento y *trailer* ≤ 8 KB; ≤ 100 cabeceras (y, aparte, 100 *trailers* en una respuesta `chunked`); ≤ 64 KB de cabeceras en conjunto. Superarlos es una respuesta mal formada → `UNKNOWN`, nunca una excepción hacia el cliente.

Todos los límites son configurables (`pdfvalidator.revocation.*`, §4).

**Verificación real de la respuesta:**

- **OCSP** (`OcspClient`, RFC 6960): petición con *nonce* aleatorio de 16 bytes por POST. Antes de confiar se comprueba que el respondedor sea el emisor o un delegado con `id-kp-OCSPSigning`, la firma de la respuesta, que el `CertID` coincida, la frescura de `thisUpdate`/`nextUpdate` (margen de reloj de 5 min) y el *nonce* si se devuelve.
- **CRL** (`CrlClient`, RFC 5280): descarga por GET, parseo con `CertificateFactory`, verificación de la firma con la clave del emisor, comprobación de `nextUpdate` (mismo margen) y búsqueda del número de serie entre las entradas revocadas.

**Guarda SSRF con conexión anclada.** Las URLs OCSP/CRL vienen de extensiones de un certificado potencialmente hostil, así que `RevocationUrlGuard`:

- Solo acepta `http` (nunca `https`, ver §10).
- Resuelve el host **una sola vez** y descarta las direcciones privadas o reservadas: *loopback*, enlace local (incluida la de metadatos de nube `169.254.169.254`), RFC 1918, `0.0.0.0/8`, CGNAT, multidifusión e IPv6 *unique-local*, también disfrazadas dentro de IPv6: IPv4 mapeada (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`), NAT64 (`64:ff9b::/96`; el prefijo de uso local `64:ff9b:1::/48` se rechaza entero) y 6to4 (`2002::/16`) (T21: estas tres últimas formas no se normalizaban y saltaban la lista). Teredo no se decodifica. Un pentest dinámico confirmó el bloqueo de `127.0.0.1`, `169.254.169.254`, `[::1]`, `[::ffff:127.0.0.1]`, `0.0.0.0`, `2130706433` y `localhost`.
- Devuelve la dirección elegida (`ValidatedTarget`) y `PinnedHttpClient`, un cliente HTTP/1.1 mínimo sobre `java.net.Socket`, conecta exactamente a ella y nunca vuelve a resolver el nombre. Así un DNS hostil que responda distinto en dos resoluciones (*DNS rebinding*) no puede sortear la guarda. Nunca sigue redirecciones.
- El filtro de direcciones privadas solo se desactiva con un constructor de solo-test, inalcanzable desde el cableado de producción.

**Puerta de confianza.** La revocación solo se comprueba para una cadena `TRUSTED`. Las URLs OCSP/CRL de una cadena de confianza las escribió una CA real, no quien subió el documento, lo que cierra el vector principal de SSRF (un certificado autofirmado con una URL interna nunca llega a `TRUSTED`); la guarda de red queda como defensa en profundidad. Además, certificado y emisor se toman de `validatedPath` (§2.7), nunca de la cadena que trae el CMS: un CMS hostil podría embeber un certificado adicional ajeno a la ruta real.

La revocación no consulta la Lista de Confianza: se comprueba OCSP/CRL contra el emisor tal como aparece en el certificado. La TSL solo decide qué anclas se empaquetan (§2.7).

### 2.9 Validación formal PDF/A-1b (*preflight*)

PDF/A es el estándar de archivo a largo plazo. `infrastructure/preflight/PreflightPdfaValidator` implementa `PdfaConformanceValidator` con el módulo *preflight* de PDFBox y valida **siempre** contra PDF/A-1b, sin mirar la declaración XMP para decidir si validar.

**Por qué solo PDF/A-1b.** *Preflight* 3.0.8 solo valida formalmente PDF/A-1a/1b. Un documento que declare PDF/A-2 o PDF/A-3 se valida igualmente contra las reglas 1b (casi seguro no las cumple); por eso el caso de uso (§2.11) decide qué hacer con ese resultado.

**Qué comprueba** (a grandes rasgos): fuentes embebidas, un `OutputIntent` con perfil de color, ausencia de flujos de referencias cruzadas comprimidos (PDF/A-1 se basa en PDF 1.4), metadatos XMP presentes y coherentes, sin cifrado, entre otras reglas.

**Resultado y robustez.** Un documento individual nunca provoca una excepción salvo una entrada que ni siquiera declara cabecera `%PDF-x.y` (lanza `InvalidPdfException`). Un documento cifrado, roto con cabecera o un fallo interno de *preflight* se informan como `NOT_VALIDATED` con una incidencia explicativa de texto fijo (*"The document declares a PDF header but could not be parsed"*, *"PDF/A-1b validation failed"*, ...): el mensaje del *parser* de PDFBox puede reproducir contenido del documento, así que solo se registra en el log del servidor, con los saltos de línea y caracteres de control sustituidos y a 300 caracteres como máximo (T23). Solo el mensaje de «demasiado complejo» incluye texto propio (los límites configurados de tamaño decodificado). Antes de invocar *preflight* se carga el documento una vez con PDFBox normal para distinguir cifrado de "cabecera presente pero roto"; eso supone un segundo parseo, un coste aceptado y acotado por el tamaño máximo de subida.

**Bombas de descompresión (T18a).** Un PDF de 510 KB cuyo flujo de contenido `/FlateDecode` se expandía a 500 MB agotaba el *heap* dentro de *preflight* (`PDFStreamParser` construye un único *token* gigante), y con `-XX:+ExitOnOutOfMemoryError` cada subida así mataba la JVM. Se comprobó en el código de PDFBox 3.0.8 que el *stream cache* (`MemoryUsageSetting`/`StreamCacheCreateFunction`) solo afecta a la **escritura** de flujos: al **decodificar**, `Filter.decode` acumula todo el resultado en memoria, así que acotar la caché no lo evita. Por eso `infrastructure/pdfbox/DecodedSizeGuard` decodifica una vez, antes de *preflight*, cada flujo del documento con un decodificador en *streaming* que **cuenta y descarta** los bytes (nunca los materializa) y rechaza el documento en cuanto se cruza un límite. Solo se aplican los filtros de expansión sin pérdida (Flate, LZW, ASCII85, ASCIIHex, RunLength); en una cadena de filtros, las etapas intermedias usan un búfer acotado al límite por flujo. Los flujos `/Subtype /Image` quedan exentos del límite por flujo (los escaneos grandes son legítimos y *preflight* no los materializa) pero cuentan en el total. Si se supera un límite, el informe PDF/A es `NOT_VALIDATED` con la incidencia `DOCUMENT_TOO_COMPLEX`, el resto del informe se genera con normalidad y la respuesta es `200`. La lectura del XMP (`PdfBoxDocumentReader`, y la declaración dentro de *preflight*) usa la misma decodificación acotada: un XMP que es una bomba se lee como «sin declaración PDF/A». Los límites son `pdfvalidator.analysis.max-decoded-stream-size` (32 MB por flujo) y `pdfvalidator.analysis.max-decoded-total-size` (2 GB en total, que acota también el tiempo de CPU).

**Incidencias.** Cada resultado no conforme trae una lista de `PdfaIssue` (código + mensaje) deduplicada y acotada a 200 elementos (con una incidencia `TRUNCATED` que indica cuántas se omitieron).

**Incidencias bilingües.** Cada incidencia lleva `code`, `message` (texto original en inglés de PDFBox) y `messageEs` (descripción en español o `null`). La traducción la resuelve `domain/model/PdfaIssueCatalog`, un catálogo de datos puro con una entrada por cada código `ERROR_*` de `PreflightConstants` de *preflight* 3.0.8; si un código no existe, sube por su categoría (`3.1.99` → `3.1` → `3`). Un código sin traducción (`-1`, `NOT_VALIDATED`, `TRUNCATED`) devuelve `messageEs = null` y nunca se inventa una. La interfaz muestra primero el español y debajo, en cursiva, el original en inglés (`lang="en"`).

**Límite de incidencias (T20).** El informe conserva como máximo `max-pdfa-issues` incidencias distintas (200): el límite se aplica **mientras se recogen** los errores de *preflight* (antes se acumulaban todas las únicas en un mapa y solo después se recortaba). Las incidencias omitidas se resumen en una incidencia `TRUNCATED` con «N additional issue(s) omitted»; para no crecer sin límite, solo se recuerdan las primeras 1 000 omitidas distintas, y por encima el mensaje pasa a «at least N additional issue(s) omitted» (cota inferior). Nota honesta: la lista de errores original ya la guarda *preflight* en memoria antes de llamarnos; el límite acota lo que este adaptador añade encima (mapa de claves e incidencias), no esa lista.

### 2.10 Veredicto general por firma

El veredicto resume en una sola palabra qué se puede concluir de cada firma, con sus motivos. `domain/policy/SignatureVerdictPolicy` (política de dominio pura) combina `IntegrityStatus`, `ChainStatus` y `RevocationStatus` de cada firma ya enriquecida en un `SignatureVerdict`, más un `OverallVerdict` a nivel de documento, según esta tabla (de arriba abajo; la primera fila que aplica decide):

| Condición | Veredicto | Motivo (`verdictReasons`) |
|---|---|---|
| `INVALID_SIGNATURE` | ❌ `INVALID` | `SIGNATURE_INVALID` |
| `UNSUPPORTED` (subfiltro no soportado) | ⚠️ `NOT_ADMITTED` | `SIGNATURE_FORMAT_UNSUPPORTED` |
| `MODIFIED_AFTER_SIGNING`, no existe ninguna firma posterior | ❌ `INVALID` | `MODIFIED_AFTER_LAST_SIGNATURE` |
| `MODIFIED_AFTER_SIGNING`, existe alguna firma posterior pero **no todas** están admitidas (veredicto `VALID` completo) | ❌ `INVALID` | `MODIFIED_AFTER_SIGNING_BY_UNADMITTED_PARTY` |
| `MODIFIED_AFTER_SIGNING`, existe al menos una firma posterior y **todas** están admitidas | *(continúa con cadena/revocación)* | `COVERED_BY_LATER_SIGNATURE` (informativo) |
| Sin sello de tiempo de confianza (se añade antes de las filas de cadena) | *(no cambia el veredicto)* | `VALIDATED_AT_CURRENT_TIME` (informativo: la cadena se validó a fecha de hoy) |
| Integra, cadena `UNTRUSTED_ROOT` / `INCOMPLETE_CHAIN` / `EXPIRED` / `NOT_CHECKED` | ⚠️ `NOT_ADMITTED` | `CHAIN_UNTRUSTED_ROOT` / `CHAIN_INCOMPLETE` / `CHAIN_EXPIRED` / `CHAIN_NOT_CHECKED` |
| Cadena `TRUSTED`, revocación no solicitada | ✅ `VALID` | `REVOCATION_NOT_REQUESTED` (informativo: la interfaz dice "revocación no comprobada") |
| Cadena `TRUSTED`, revocación solicitada, `GOOD` | ✅ `VALID` | — |
| Cadena `TRUSTED`, revocación solicitada, `REVOKED` | ❌ `INVALID` | `REVOCATION_REVOKED` |
| Cadena `TRUSTED`, revocación solicitada, `UNKNOWN` | ⚠️ `NOT_ADMITTED` | `REVOCATION_UNKNOWN` |
| Cadena `TRUSTED`, revocación solicitada, sigue en `NOT_CHECKED` (p. ej. ruta validada vacía) | ⚠️ `NOT_ADMITTED` | `REVOCATION_UNAVAILABLE` |

`OverallVerdict` (documento) es el peor veredicto entre las firmas (`INVALID` > `NOT_ADMITTED` > `VALID`), `NO_SIGNATURES` si no hay ninguna, o `ANALYSIS_INCOMPLETE` cuando la sección `SIGNATURES` falló de forma inesperada o quedaron campos de firma sin analizar por el límite `max-signature-fields` (`sectionErrors`, T20): una lista vacía por ese fallo nunca se confunde con "documento sin firmar". `PdfAnalysisReport.modifiedAfterLastSignature()` expone aparte el hecho estructural de que ninguna firma alcanza el final real del fichero.

**Decisiones explícitas:**

- **`UNSUPPORTED` es `NOT_ADMITTED`, no `INVALID`:** un subfiltro desconocido significa que el servicio no pudo verificar la firma, no que esté mal.
- **`REVOKED` es siempre `INVALID`.** Salvedad: se consulta el estado de revocación **actual** (§2.8), no el del instante de firma; un certificado revocado después de firmar válidamente aparecerá como `REVOKED`.
- **Sin sello de confianza se valida a fecha de hoy (T19).** `VALIDATED_AT_CURRENT_TIME` aparece en toda firma que llega a la comprobación de cadena y no tiene un sello `trusted`; la interfaz lo muestra como «Sin sello de tiempo de confianza: se ha validado a fecha de hoy».
- **Regla de varias firmas.** Una firma anterior con `MODIFIED_AFTER_SIGNING` solo se exime de penalización si **todas** las firmas posteriores están ellas mismas admitidas (`VALID`), no basta con que sean `INTACT`. Motivo de seguridad: si solo se exigiera `INTACT`, un atacante podría modificar un documento firmado por una entidad de confianza y volver a firmarlo con un certificado autofirmado propio, y la firma original seguiría pareciendo `VALID`.
- **Limitación:** la regla es estructural (el `ByteRange` de la firma posterior llega al final, su CMS verifica y su cadena/revocación son de confianza); **no** compara el contenido añadido entre revisiones.

### 2.11 Orquestación: `AnalyzePdfUseCase`

`application/AnalyzePdfUseCase` es el director de orquesta: en un único método `analyze(fileName, content, options)` llama a todos los puertos en este orden: hashes → estructura/seguridad/declaración PDF/A → validación formal PDF/A-1b → firmas (cada una enriquecida con cadena y, opcionalmente, revocación) → veredicto. Recibe un `java.time.Clock` inyectado, para que `analyzedAt` y el "ahora" usado como último recurso sean deterministas en los tests.

- **Confianza del sello y `validationTime` de la cadena (T19).** Antes de validar la cadena del firmante, `assessTimestamp` decide si el sello es de confianza (§2.6), validando la cadena de la TSA en su `genTime` a través del mismo puerto. El `validationTime` del firmante es el `genTime` **solo si el sello es de confianza**; si no, el instante actual del `Clock`. La fecha auto-declarada (`claimedSigningTime`) no interviene. Si la validación de la cadena de la TSA lanza una excepción, el sello queda como no de confianza y el resto de la firma se conserva.
- **PDF/A combinado.** Se lee la declaración XMP antes de invocar el validador formal. Si declara PDF/A-2 o -3 (`part != 1`), no se llama a *preflight* y el informe es `NOT_VALIDATED` con la incidencia `PDFA_PART_NOT_SUPPORTED`, indicando que solo se valida formalmente PDF/A-1b. Si declara PDF/A-1 o nada, se usa el resultado formal.
- **Revocación.** Con `checkRevocation=false`, cada firma recibe `notChecked()`. Con `true`, solo se llama al `RevocationChecker` cuando la cadena es `TRUSTED`; en otro caso se informa `NOT_CHECKED` con *"revocation not checked: certificate chain is not trusted"*, y los certificados a comprobar (todos los de la ruta salvo el ancla, cada uno con su emisor) salen de `validatedPath` (§2.8).
- **Documento cifrado o corrupto: se propaga, no se atrapa.** `EncryptedPdfException` e `InvalidPdfException` salen de `analyze(...)`: no hay informe parcial razonable para un documento que no se pudo abrir. La capa REST las mapea a `422` (§2.13).
- **El fallo de una sección no pierde el resto.** Una excepción inesperada del validador PDF/A se informa como `NOT_VALIDATED`; una del verificador de firmas, como lista vacía; y una del enriquecimiento de una firma (cadena + revocación) deja esa firma con sus campos de integridad intactos y añade una nota a `anomaly`. En los dos primeros casos se añade además un `SectionError` (`PDFA`/`SIGNATURES`) al informe. Solo el cálculo de hashes carece de guarda: no puede fallar de forma significativa. El texto que llega al cliente es siempre fijo (*"PDF/A-1b validation failed unexpectedly"*, ...); el detalle real va al log.
- **Veredicto final.** Tras enriquecer todas las firmas, una última pasada con `SignatureVerdictPolicy.evaluateAll(...)` (necesita verlas juntas, §2.10). `overallVerdict()` y `modifiedAfterLastSignature()` se calculan bajo demanda a partir de esa lista.

Los tests (`AnalyzePdfUseCaseTest` con *fakes* escritos a mano, sin Mockito, y `AnalyzePdfUseCaseIntegrationTest` con adaptadores reales contra un PDF firmado y sellado en tiempo real) cubren orquestación, `validationTime`, revocación, PDF/A-2/3, aislamiento de fallos y propagación de excepciones (§7).

### 2.12 Arquitectura hexagonal comprobada con ArchUnit

`src/test/java/.../architecture/ArchitectureTest` comprueba automáticamente en cada `./mvnw verify` que cada capa solo depende de lo que debe:

- **`domain` no depende de nada salvo Java puro:** ni Spring, ni PDFBox, ni Bouncy Castle, y tampoco `java.security.cert` ni `java.awt`.
- **`application` depende solo de `domain` y Java puro:** orquesta puertos, nunca un adaptador concreto.
- **`infrastructure` nunca depende de `application` ni de `api`.**
- **`api` solo depende de `application`, `domain`, Spring MVC y las anotaciones de springdoc/swagger,** nunca de `infrastructure`.
- **Sin ciclos** entre `domain`, `application`, `infrastructure` y `api`.

Las reglas excluyen los propios tests (`DO_NOT_INCLUDE_TESTS`): los *fixtures* usan PDFBox/Bouncy Castle a propósito.

### 2.13 API REST y cableado Spring

**Endpoint único:** `POST /api/v1/pdf/analyze` (`api/PdfAnalysisController`), `multipart/form-data` con el campo `file` y el parámetro opcional `checkRevocation` (por defecto `false`). No confía en el nombre del fichero: comprueba los bytes en busca de una cabecera `%PDF-` en los primeros 1024 bytes, así que un `factura.pdf` que no sea un PDF se rechaza.

**DTOs explícitos** (`api/dto/`): `PdfAnalysisReportMapper` traduce `PdfAnalysisReport` a `PdfAnalysisReportDto` campo a campo, con nombres JSON estables (`camelCase`). Los enumerados del dominio se exponen como texto (`"INTACT"`, `"TRUSTED"`, ...). Un `CertificateInfo` nunca expone su DER; se expone una huella `sha256Fingerprint`.

**Errores** (`api/error/`, RFC 9457 `ProblemDetail`): la tabla completa está en §4 («Errores de la API»). Decisiones de diseño:

- `PdfAnalysisExceptionHandler` es un `@RestControllerAdvice(assignableTypes = PdfAnalysisController.class)`: sin acotar, su `@ExceptionHandler(Exception.class)` afectaría a toda la aplicación y convertiría un `404` legítimo de Actuator en `500`.
- El `413` tiene su propio *advice* sin acotar, `MaxUploadSizeExceptionHandler`, porque Spring resuelve el multipart *antes* de elegir controlador y el *advice* acotado nunca vería `MaxUploadSizeExceededException`; solo reacciona a esa excepción.
- Un `IOException` leyendo el fichero subido es un `500` (fallo del servidor), no un `400` de fichero ausente. Ningún mensaje de excepción llega al cliente.

**Límite de análisis simultáneos.** `AnalysisBulkheadFilter` (`api/concurrency`) aplica un *bulkhead* a toda petición `multipart/*` antes de que Spring lea la subida; ver «Límite de análisis simultáneos» en §4.

**Cableado** (`infrastructure/config/AdapterConfiguration` + `com.coam.pdfvalidator.UseCaseConfiguration`): `AdapterConfiguration` declara un `@Bean` por cada adaptador. `AnalyzePdfUseCase` se cablea en `UseCaseConfiguration`, en el paquete raíz, **fuera** de las cuatro capas, porque `infrastructure` no puede depender de `application` y ese `@Bean` depende de ambas (la "raíz de composición" de una arquitectura hexagonal). Las propiedades se enlazan con `TrustStoreProperties`, `RevocationProperties` y `AnalysisProperties` (§4, «Configuración»).

**OpenAPI** (`OpenApiConfiguration`): título, descripción y licencia GPL-3.0; la versión se lee de `BuildProperties` (objetivo `build-info` de `spring-boot-maven-plugin`) con una constante de respaldo.

### 2.14 Interfaz web «Validar»

La pantalla «Validar» es la forma normal de usar el servicio: arrastras un PDF y ves un informe legible con un veredicto claro. Se sirve como ficheros estáticos de Spring Boot (`src/main/resources/static/`), sin *build step*, sin *frameworks* y sin CDNs: JavaScript nativo con módulos ES, HTML y CSS.

- **Cómo abrirla:** con la aplicación arrancada (§4), <http://localhost:8963/> (o `/index.html`).
- **Qué muestra:** una zona de arrastrar-y-soltar (o clic) para un PDF de hasta 80 MB, la casilla «Comprobar revocación (OCSP/CRL)» y el botón «Analizar PDF» (`POST /api/v1/pdf/analyze`). El resultado incluye, en orden: un **banner de veredicto general** (✅ *Firma válida* / ⚠️ *Firma no admitida* / ❌ *Firma inválida* / *Documento sin firmas* / ⚠️ *Análisis incompleto*) con sus motivos en español llano; una tarjeta por firma (firmante con su nombre común en negrita, emisor, fecha declarada (marcada como no verificada), sello de tiempo —etiquetado «Sello de tiempo (TSA no de confianza)» cuando no es de confianza, con el motivo en los detalles técnicos—, integridad, cadena, revocación, motivos y anomalías) con un desplegable de detalles técnicos (cadena completa con CN, DN y huellas SHA-256, cobertura del `ByteRange`); una sección de documento (hashes con botón de copiar, versión, **páginas agrupadas** y **Recortes** (ver abajo), **Cifrado y permisos** —«Cifrado: No» en una línea y permisos traducidos al español—, resultado PDF/A con sus incidencias bilingües); los `sectionErrors` como avisos; y un botón para descargar el informe JSON.
- **Traducción:** los códigos de motivo (`CHAIN_EXPIRED`, `REVOCATION_UNKNOWN`, ...), los estados y los permisos se traducen al español en `render.js` (`REASON_TEXT`, `PERMISSION_TEXT`, ...); el backend solo expone códigos estables.
- **Tema claro/oscuro:** variables CSS (`prefers-color-scheme` más un botón manual que persiste la elección en `localStorage`, dentro de `try`/`catch`).
- **Accesibilidad:** HTML semántico, zona de arrastre operable por teclado, regiones `aria-live`, ningún estado se transmite solo por color, contraste WCAG AA en ambos temas.
- **Robustez:** se ignora un segundo envío mientras hay una petición en curso; una respuesta `2xx` con forma inesperada muestra un error en español; seleccionar un fichero inválido (no PDF o de más de 80 MB) limpia la selección anterior; los DN largos y las huellas no desbordan las tarjetas; un `503` `busy` se muestra como «El servicio está ocupado analizando otros documentos».
- **Seguridad:** toda cadena que pueda venir del PDF (nombre de firmante, campo, anomalía) se renderiza con `textContent`, nunca `innerHTML`. `infrastructure/web/CspHeaderFilter` añade `Content-Security-Policy` solo a las rutas exactas `/`, `/index.html`, `/app.js` y `/styles.css` (comparadas relativas al *context path*), sin afectar a Swagger UI, Actuator ni al endpoint de análisis. También fuerza `charset=UTF-8` en esas rutas (la alternativa, una propiedad global, forzaría el *charset* en el JSON de la API). El pie de página es neutro: nombre del proyecto y enlace al repositorio. Además, `infrastructure/web/SecurityHeadersFilter` añade a **todas** las respuestas (interfaz, API, errores y Actuator, también las cortocircuitadas como el `503` o el `413`) `X-Content-Type-Options: nosniff` y `Referrer-Policy: no-referrer` (T18d); no se añade `X-Frame-Options` porque la CSP ya envía `frame-ancestors 'none'`.
- **Páginas agrupadas y recortes (T22):** la tarjeta «Estructura del documento» ya no lista una fila por página. Las páginas con la misma rotación y el mismo tamaño (`MediaBox` redondeado) se agrupan en una sola pasada, en orden de primera aparición, y cada grupo es un `<details>` **cerrado por defecto** (operable con teclado) cuyo resumen dice, por ejemplo, «13 páginas · 595 × 842 pt (A4) · Vertical · 0°»; al abrirlo se ven los números de página compactados en rangos («1–12, 15, 20–22», con raya en «–»). El nombre de papel (A5, A4, A3, A2, Letter, Legal, en cualquier orientación, ±2 pt) solo se añade para tamaños conocidos. Una rotación no válida (`rotationValid=false`) forma su propio grupo por valor bruto, con el texto «45° (no válida, se trata como 0°)» y una etiqueta «Rotación no válida» (texto, no solo color). La tarjeta nueva **«Recortes»** lista solo las páginas cuyo `CropBox` difiere del `MediaBox` (tolerancia 0,5 pt en las cuatro coordenadas), agrupadas si comparten exactamente la misma geometría: páginas, tamaño de página, tamaño visible y puntos recortados a izquierda, abajo, derecha y arriba; sin ninguna, «Ninguna página tiene recorte.». Si `structure.pagesTruncated` es `true`, ambas tarjetas avisan de que solo se han considerado las primeras N páginas (T20). La lógica pura (agrupar, rangos, recortes, nombre de papel) está en `pages.js`; `render.js` solo construye el DOM con `textContent`.
- **Módulos:** `app.js` (punto de entrada: tema y pestañas), `dom.js` (DOM y utilidades compartidas, `switchTab`), `pages.js` (lógica pura de grupos de páginas y recortes), `render.js` (renderizado del informe), `validate.js` («Validar», exporta `analyzeFile()`), `sign.js` («Firmar»).

Los tests cubren la política de veredicto, el mapeo JSON y la cabecera CSP (`StaticContentSecurityTest`, `CspHeaderFilterTest`, §7). La interfaz en sí no tiene tests JS automatizados y se verifica manualmente en el navegador.

### 2.15 Pantalla «Firmar» (AutoFirma)

Permite firmar un PDF con el propio certificado del usuario (DNIe, FNMT, ...) usando **AutoFirma**, la aplicación de escritorio oficial, y validar el resultado con un clic. Es la misma página que «Validar» con una segunda pestaña (`static/index.html`), para reutilizar cabecera, tema, filtro CSP y el renderizado del informe.

- **Flujo:** el usuario elige un PDF (≤ 80 MB; se comprueban extensión/MIME y los 5 primeros bytes `%PDF-`, porque el fichero nunca llega al servidor) → se lee como base64 → `AutoScript.sign(dataB64, "SHA256withRSA", "PAdES", extraParams, ...)` invoca AutoFirma en su equipo, que abre su propio selector de certificado → AutoFirma devuelve el PDF firmado → «Descargar PDF firmado» (`<original>-firmado.pdf`) y «Validar este PDF», que envía esos bytes a `POST /api/v1/pdf/analyze` reutilizando `analyzeFile()` de `validate.js` y cambia a la pestaña «Validar».
- **Privacidad:** la clave privada nunca sale del equipo del usuario, no interviene ningún servidor intermedio de guardado/recuperación y el servicio solo recibe el PDF firmado si el usuario pulsa «Validar este PDF». La pantalla lo explica en una frase visible.
- **Firma invisible** por defecto; un campo opcional «Motivo de la firma» se envía como `signReason` (con tildes y ñ correctas).
- **Espera y errores en español:** mientras AutoFirma responde se muestra «Esperando a AutoFirma...» con un botón «Cancelar» (la página deja de esperar y descarta cualquier respuesta tardía). Se traducen: operación cancelada, AutoFirma no instalado o sin responder (con el enlace oficial de descarga <https://firmaelectronica.gob.es/Home/Descargas.html>), documento no válido y un motivo genérico que muestra el error real. Una respuesta de éxito corrupta muestra «AutoFirma devolvió una respuesta que no se pudo interpretar».
- **Foco y accesibilidad:** al terminar la validación el foco pasa a `#results-heading` (con *scroll* que respeta `prefers-reduced-motion`); un contador (`validationToken`) evita que una validación tardía mueva el foco tras cancelar o elegir otro archivo.
- **CSP:** sin `'unsafe-eval'` ni `'unsafe-inline'` para scripts. La política completa es `default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; connect-src 'self' wss://127.0.0.1:* https://127.0.0.1:*; frame-src 'self' afirma:`. Las dos últimas directivas son las únicas que AutoScript necesita (§10).
- **AutoScript** (1.10.1) se incluye sin modificar como componente de terceros (`static/vendor/autofirma/`, §13). Se inicializa con `AutoScript.cargarAppAfirma()` **sin** `setForceWSMode(true)` y con `SupportDialog.enableSupportDialog(false)` (§10).

## 3. Stack tecnológico

| Área | Tecnología | Versión |
|---|---|---|
| Lenguaje | Java (LTS) | 25 |
| Framework | Spring Boot (Web MVC, Validation, Actuator) | 4.1.1 |
| Motor PDF | Apache PDFBox | 3.0.8 |
| Validación PDF/A | Apache PDFBox *preflight* (PDF/A-1b) | 3.0.8 |
| Criptografía | Bouncy Castle `bcprov` / `bcpkix` (jdk18on) | 1.86 |
| Servidor embebido | Apache Tomcat (sobrescrito, ver «Dependencias parcheadas» en §10) | 11.0.26 |
| Serialización JSON | Jackson 3 / Jackson 2 (esta última vía springdoc; sobrescritas, ver §10) | 3.1.7 / 2.21.6 |
| Documentación API | springdoc-openapi (Swagger UI) | 3.1.1 |
| Tests | JUnit 5, AssertJ, Mockito, ArchUnit | — / 1.5.1 |
| Cobertura | JaCoCo (con umbral mínimo que hace fallar la compilación) | 0.8.15 |
| Análisis estático | SpotBugs + FindSecBugs, PMD + CPD (solo informan), CodeQL en CI | 4.10.4 / 1.14.0, 7.28.0, — |
| Pruebas de mutación | PIT (perfil Maven `mutation`, fuera de la compilación normal) | 1.30.0 |
| Build | Maven (wrapper incluido) | 3.9.9 |
| CI | GitHub Actions (Temurin 25) | — |
| Despliegue | VPS OVHcloud VPS-1 (Ubuntu 24.04, 4 GB), Docker Compose, `ufw`, SSH solo con clave | ✅ (§4) |
| Contenedor | Docker multi-etapa (`eclipse-temurin:25-jdk-alpine` para compilar, `eclipse-temurin:25-jre-alpine` para ejecutar), Docker Compose | ✅ (probado en CI y en un VPS, ver §4) |
| Frontend | HTML + CSS + JavaScript nativo (módulos ES, sin frameworks, sin CDNs) | ✅ (pantallas "Validar" y "Firmar") |
| Firma de escritorio | AutoScript (Cliente @firma / AutoFirma), vendida como componente de terceros sin modificar | 1.10.1 (§13) |


## 4. Instalación y ejecución

### Requisitos

- **JDK 25** (en desarrollo se usa OpenLogic OpenJDK 25; en CI y en el contenedor, Eclipse Temurin 25).
- No hace falta instalar Maven: el proyecto incluye el wrapper (`mvnw` / `mvnw.cmd`).

> Si en tu máquina el `java` por defecto es otra versión, define `JAVA_HOME` apuntando al JDK 25 antes de usar el wrapper.

### Compilar y ejecutar los tests

```bash
# Linux / macOS / Git Bash
./mvnw verify

# Windows (cmd / PowerShell)
mvnw.cmd verify
```

`verify` compila, ejecuta todos los tests y genera el informe de cobertura en `target/site/jacoco/index.html`.

### Arrancar la aplicación

```bash
# Linux / macOS / Git Bash -- asegúrate de que JAVA_HOME apunta al JDK 25
export JAVA_HOME="/ruta/al/jdk-25"
export PATH="$JAVA_HOME/bin:$PATH"

./mvnw spring-boot:run
```

Con la configuración por defecto (`application.yml`), una vez arrancada:

- Interfaz web («Validar» y «Firmar»): <http://localhost:8963/> (o `/index.html`), ver §2.14 y §2.15.
- API REST: `POST http://localhost:8963/api/v1/pdf/analyze`
- **Puerto por defecto: 8963** (se evita el 8080 porque suele chocar con otros servidores locales, como WildFly). Para cambiarlo: variable de entorno `SERVER_PORT=9000` o `java -jar ... --server.port=9000`.
- Swagger UI: <http://localhost:8963/swagger-ui.html>
- Especificación OpenAPI: <http://localhost:8963/v3/api-docs>
- Estado de la aplicación (Actuator, solo `health`/`info` expuestos): <http://localhost:8963/actuator/health>, <http://localhost:8963/actuator/info>
- Docker / Docker Compose: ver «Ejecución con Docker» más abajo.

### Regenerar el almacén de confianza desde las Listas de Confianza (T14)

Herramienta de mantenimiento, **no** una función del servidor: su código está en `src/test/java/com/coam/pdfvalidator/tools/tsl/` (lo prueba el `verify` normal, sin red) y se ejecuta con el *classpath* de test, así que nunca llega al jar ni a la imagen Docker. Un único comando:

```bash
./mvnw -q -Ptsl-sync
```

Descarga por HTTPS la LOTL de la UE (`https://ec.europa.eu/tools/lotl/eu-lotl.xml`) y la TSL española a la que apunta (`https://tsl.digital.gob.es/TSL.xml`), verifica la firma XML de las dos y **sustituye por completo** `src/main/resources/truststore/` (anclas `.crt`, `index.txt` y `SOURCES.md`; reglas de selección en §2.7). Si nada cambió en las listas, la salida es idéntica byte a byte (sin marcas de tiempo de ejecución; los ficheros se fijan a LF en `.gitattributes`), así que `git status` queda limpio. Después, `./mvnw verify` y revisar el diff de `SOURCES.md`.

Comprobaciones de seguridad (cualquier fallo aborta **sin tocar** el almacén: todo se descarga, verifica y genera en memoria y solo al final se escribe, pasando por un directorio temporal):

- **Descarga:** solo HTTPS con validación PKIX normal de la JDK y del nombre de host, sin seguir redirecciones, con plazos (conexión 20 s, respuesta 60 s, cuerpo 120 s) y tope de 20 MB. La confianza TLS es el `cacerts` de la JDK más **una** raíz fijada por SHA-256, AC RAIZ FNMT-RCM (`src/test/resources/.../tls-root-ac-raiz-fnmt-rcm.crt`, descargada de la sede de FNMT y con la misma huella que su registro en CCADB): `tsl.digital.gob.es` se sirve bajo ella y la JDK no la incluye. El TLS es defensa en profundidad; lo que hace fiable una lista es su firma.
- **XML seguro:** con espacios de nombres, cualquier `DOCTYPE` rechazado (`disallow-doctype-decl`, lo que impide expansión de entidades y XXE), sin DTD, entidades ni esquemas externos, sin XInclude y con `FEATURE_SECURE_PROCESSING`.
- **Firma:** exactamente un `ds:Signature` en todo el documento, hijo directo de la raíz (envolvente); su primera `Reference` es `URI=""` (el documento entero) con solo las transformaciones *enveloped-signature* y de canonicalización (una XPath que excluyera contenido se rechaza) y el resto de referencias son internas (`#id`); solo se registran como ID el `Id` de la raíz y el de `xades:SignedProperties`; validación con `javax.xml.crypto.dsig` de la JDK y su modo *secure validation* activo.
- **Firmante:** `KeyInfo` debe traer exactamente un certificado, cuya SHA-256 se comprueba **antes** de usar su clave: para la LOTL, uno de los seis anunciados por la Comisión Europea en el Diario Oficial (OJ C/2026/1944), fijados en `TslSync.LOTL_SIGNER_SHA256`; para la TSL española, uno de los `ServiceDigitalIdentities` del puntero `OtherTSLPointer` de la LOTL ya verificada con `SchemeTerritory` `ES` y `MimeType` `application/vnd.etsi.tsl+xml` (nunca valores fijados en el código). El certificado firmante debe estar vigente y el `NextUpdate` de la lista debe ser futuro.
- **Contenido:** `SchemeTerritory` `EU` y `ES`, solo identidades `X509Certificate`, deduplicación por SHA-256 y nunca un almacén vacío.

**Pines de la LOTL y su rotación.** Las seis huellas se tomaron del primer `OtherTSLPointer` de la propia LOTL (2026-10-01), porque EUR-Lex no era accesible desde aquí. **Pendiente, a mano y una sola vez:** cotejarlas con la publicación OJ C/2026/1944 en EUR-Lex. Cuando la Comisión cambie sus certificados de firma, la herramienta falla con un mensaje que lo indica (*"The LOTL signer certificate … is not pinned … update TslSync.LOTL_SIGNER_SHA256"*); hay que tomar los nuevos certificados del aviso del Diario Oficial que los anuncie y actualizar ese conjunto (y su test). Las LOTL "pivote" de la rotación no se siguen automáticamente.

Huellas SHA-256 fijadas (`TslSync.LOTL_SIGNER_SHA256`, donde figuran sin espacios), separadas por pares de dígitos como en el Diario Oficial, para cotejar con OJ C/2026/1944 (<https://eur-lex.europa.eu/eli/C/2026/1944/oj>):

- `d2 06 4f dd 70 f6 98 2d cc 51 6b 86 d9 d5 c5 6a ea 93 94 17 c6 24 b2 e4 78 c0 b2 9d e5 4f 84 74`
- `e0 a6 20 fb b6 74 73 62 bb 93 3a c4 41 69 d6 76 a5 53 44 47 16 cf 5f 31 60 5f 12 a2 2b 83 96 b1`
- `c0 64 1c 4f 7d 56 c4 31 b1 c9 24 74 2d b7 fc e9 c1 ee f7 d7 fd 21 21 13 a2 76 84 86 b3 ab cd c5`
- `df 7e 29 36 0c 34 b2 b8 d6 d5 f4 03 25 c1 d4 d1 2c 99 22 ce cd 33 b7 40 76 74 a7 4b 2b 3c a1 e5`
- `b6 3d 41 67 44 e7 09 8b f9 ec 2c aa 59 6a 93 bc 24 68 e3 7f 82 84 ba 65 ec c0 61 71 1b cb aa 18`
- `23 61 03 f0 3a 80 31 ae 8f 47 f9 05 9b f8 de 38 56 4c db fe be dd e4 a5 97 d5 0f 89 80 aa 65 3b`

**Alcance: solo España.** La herramienta sigue únicamente el puntero de la LOTL a la Lista de Confianza española (`SchemeTerritory` `ES`). Una firma de una CA cualificada de otro Estado miembro de la UE se informa como `UNTRUSTED_ROOT` (veredicto `NOT_ADMITTED`), aunque esa CA figure en la lista de su país. Ampliarlo al resto de países sería seguir los demás punteros de la LOTL con la misma verificación; queda fuera del alcance del TFM por decisión explícita.

**Tarea semanal** (`.github/workflows/tsl-sync.yml`): cada lunes a las 05:17 UTC (y a demanda, `workflow_dispatch`) ejecuta la herramienta con JDK 25 Temurin; si `src/main/resources/truststore/` cambió, ejecuta `./mvnw -B verify` sobre el resultado, crea la rama `chore/truststore-lotl-<n>-es-tsl-<m>` y abre (o actualiza) un *pull request* con `gh pr create` y el `GITHUB_TOKEN` (`permissions: contents: write, pull-requests: write`); si el `verify` falla, el PR se abre como borrador y la ejecución termina en error. Las acciones de terceros están fijadas por SHA de commit. Requisitos y límites:

- En el repositorio debe estar activado **«Allow GitHub Actions to create and approve pull requests»** (*Settings → Actions → General → Workflow permissions*); sin ello falla el paso del PR.
- Los PR abiertos con `GITHUB_TOKEN` no disparan `ci.yml`; la tarea ya ejecuta el `verify` y lo indica en el PR. Para lanzar la CI, basta cerrar y reabrir el PR.
- Una ejecución fallida (lista caducada, firma inválida, firmante no fijado, red) es la alerta: no se abre PR y el almacén no cambia.

### Ejecución con Docker

Requiere Docker con el daemon en marcha (no hace falta JDK ni Maven en el equipo).

```bash
docker build -t pdf-validator:local .   # construir la imagen (los tests se ejecutan en CI, no aquí)
docker compose up -d --build            # arrancar (http://localhost:8963/)
docker compose ps                       # el estado pasa a "healthy" en menos de ~60 s
curl -s localhost:8963/actuator/health  # {"status":"UP",...}
docker compose logs -f                  # seguir los logs
docker compose down                     # parar y eliminar el contenedor
```

**Imagen.** `Dockerfile` multi-etapa (imágenes base fijadas por *digest* `etiqueta@sha256:...` —el índice multi-arquitectura, para que `linux/amd64` y `linux/arm64` sigan resolviendo—, con la etiqueta conservada por legibilidad; no se actualizan solas: el `Dockerfile` explica cómo refrescar el *digest* de las dos líneas `FROM` (T23). Esa compilación solo se comprueba en CI (no se ha ejecutado Docker en local); el jar tiene nombre determinista `target/pdf-validator.jar` vía `<finalName>`): la etapa de compilación usa el wrapper de Maven (la caché de dependencias solo se invalida si cambia `pom.xml`) y divide el jar con el *jarmode* `tools` de Spring Boot; la etapa de ejecución es un JRE 25 Alpine con solo las capas extraídas, arrancadas con `JarLauncher`. El `.dockerignore` deja fuera `target/`, `.git`, ficheros de herramientas locales, `odd/` y los PDF.

**Perfil de recursos oficial: subidas de hasta 80 MB, contenedor de 2 GB.** El límite de subida es de **80 MB** (`spring.servlet.multipart.max-file-size=80MB`, `max-request-size=81MB`; el cliente web valida lo mismo en `dom.js`). La imagen fija `JAVA_TOOL_OPTIONS="-XX:+UseSerialGC -Xms64m -Xmx1024m -XX:MaxMetaspaceSize=96m -XX:ReservedCodeCacheSize=48m -XX:MaxDirectMemorySize=32m -Xss512k -XX:+UseCompactObjectHeaders -XX:+ExitOnOutOfMemoryError"` y Compose limita el contenedor a **2 GB** (`mem_limit: 2g`) con un `tmpfs` de 256 MB para `/tmp`. El límite del contenedor cuenta *toda* la memoria del proceso (no solo el *heap*), así que cada región tiene un tope explícito y la suma en el peor caso queda por debajo del límite; si se superara, el kernel mataría el contenedor sin ningún error de Java.

| Región | Tope | Opción |
|---|---|---|
| *Heap* | 1024 MB | `-Xmx1024m` (`-Xms64m` inicial) |
| *Metaspace* | 96 MB | `-XX:MaxMetaspaceSize=96m` |
| Caché de código | 48 MB | `-XX:ReservedCodeCacheSize=48m` |
| *Buffers* directos | 32 MB | `-XX:MaxDirectMemorySize=32m` |
| Pilas de hilos | 20 MB | ~40 hilos (20 de Tomcat + JIT/VM/varios) × 512 KB (`-Xss512k`) |
| Nativa restante | 64 MB | *arenas* de `malloc`, estructuras del GC, CDS, libc (estimación) |
| **Subtotal JVM** | **1284 MB** | |
| `/tmp` (`tmpfs`) | 256 MB | `tmpfs: /tmp:size=256m`; cuenta contra el límite cuando se llena. Con `max-concurrent=2` caben 2 subidas de 81 MB (162 MB) y quedan ~90 MB libres |
| **Total en el peor caso** | **1540 MB** | ~500 MB de margen bajo 2048 MB |

**Mediciones con este perfil:**

- **VPS de OVHcloud de 4 GB (2026-09-29)**, PDF sintético de 83 MB generado con `LargePdfGenerator`, peticiones desde el propio servidor. Con `max-concurrent=1`, una subida → 200 en 4,7 s; 5 subidas simultáneas y `acquire-timeout=5s` → 2 × 200 y 3 × 503 `busy`, `memory.peak` del *cgroup* 753 MiB. Con `max-concurrent=2` y `acquire-timeout=30s`, 5 subidas simultáneas → **5 × 200** (4 a 14 s), `memory.peak` **1013 MiB de 2048**, sin reinicios, sin OOM-kill y sin `OutOfMemoryError`. Por eso esos son los valores por defecto: un análisis de 80 MB tarda 4-7 s, y con 5 s de espera la mayoría de las peticiones simultáneas recibían un 503, que el navegador puede mostrar como «no se puede contactar con el servidor» porque el servidor cierra la conexión sin leer el cuerpo.
- **CI (GitHub Actions, 2026-09-29)**, PDF sintético de 79 MB, 5 subidas simultáneas, `max-concurrent=2`, contenedor de 2 GB: 5 × 200, pico muestreado con `docker stats` 669,4 MiB y `memory.peak` del *cgroup* 1256,7 de 2048 MiB (61,4 %), 0 `oom_kill`, 0 reinicios.

Para una VM pequeña, sobrescribe `JAVA_TOOL_OPTIONS`, `mem_limit` y el `tmpfs` a la vez, y baja el límite de subida y `max-concurrent`. El perfil anterior (512 MB, PDF de ~20 MB, un análisis a la vez) y por qué se abandonó están en §10.

Otras opciones: `-XX:+UseSerialGC` (sin hilos de GC paralelos, menor consumo en una VM pequeña), `-XX:+UseCompactObjectHeaders` (cabeceras de objeto compactas, estable en Java 25) y `-XX:+ExitOnOutOfMemoryError` (ante un `OutOfMemoryError` la JVM termina y `restart: unless-stopped` la levanta, en vez de quedar en un estado degradado). La concurrencia de Tomcat está acotada en `application.yml` (`server.tomcat.threads.max: 20`, `server.tomcat.accept-count: 20`; sobrescribibles con `SERVER_TOMCAT_THREADS_MAX` y `SERVER_TOMCAT_ACCEPT_COUNT`) para que el término de hilos y el uso de `/tmp` se mantengan dentro del presupuesto.

**Límite de análisis simultáneos (*bulkhead*).** Un PDF se lee entero y PDFBox y *preflight* multiplican esa memoria; los 20 hilos de Tomcat, por sí solos, admitirían 20 análisis a la vez, muy por encima del *heap*. Por eso solo se permiten `pdfvalidator.analysis.max-concurrent` análisis simultáneos (por defecto **2**), implementado como un filtro de servlet (`AnalysisBulkheadFilter`, capa `api`) que toma un permiso de un `Semaphore` (`AnalysisBulkhead`) **antes** de que Spring lea la subida multiparte y lo libera siempre en un `finally` (éxito, excepción o cliente que se desconecta). Una petición espera hasta `pdfvalidator.analysis.acquire-timeout` (por defecto **30 s**) un permiso; si no lo consigue, responde **503** con `ProblemDetail` `urn:pdfvalidator:error:busy` y la cabecera `Retry-After` (el *timeout* en segundos, mínimo 1). La interfaz web lo muestra como «El servicio está ocupado analizando otros documentos. Inténtalo de nuevo en unos segundos.».

- *Por qué un filtro y no el controlador:* Spring resuelve el multiparte *antes* de invocar al controlador, así que un permiso tomado allí dejaría hasta 20 subidas ya almacenadas. Con el filtro, tanto el almacenamiento de la subida como el análisis quedan acotados a `max-concurrent`.
- *Alcance:* se aplica a **toda petición `multipart/*`, en cualquier ruta**, no a la URL exacta del *endpoint*. Comparar la ruta era una vía de evasión (`;jsessionid=x`, `/%61nalyze`, barra final, segmentos duplicados o de punto, mayúsculas); decidir por tipo de contenido falla en el lado seguro, porque el único *endpoint* multiparte es la subida de análisis. Comprobado contra el servidor real (`AnalysisBulkheadIntegrationTest`): con el permiso ocupado, todas esas variantes responden 503.
- *Rechazo sin leer el cuerpo:* el `503` lleva `Connection: close` y el contenedor cierra la conexión en vez de intentar vaciar la subida.
- *Búfer de subida:* `file-size-threshold=0B` y `location=${java.io.tmpdir}`: cada subida se escribe directamente a `/tmp` (tmpfs), no al *heap*, que se reserva para PDFBox. Un `tmpfs` lleno da un `IOException` (500 controlado); un *heap* lleno mata el proceso.
- *Tomcat:* `threads.max=20` y `accept-count=20` solo **encolan** conexiones. Un hilo que espera permiso permanece bloqueado como máximo `acquire-timeout`, antes de leer el cuerpo, así que las peticiones en espera no consumen *heap* ni `/tmp`. El *bulkhead* es lo que realmente acota la memoria.
- *Subidas lentas (T26b):* el permiso se toma **antes** de leer el cuerpo multiparte, así que un cliente que anuncia un cuerpo y deja de enviarlo retendría el hueco. Dos defensas, una por capa: `server.tomcat.connection-timeout=20s` (por defecto de Tomcat: 60 s) corta la petición si pasan 20 s sin recibir bytes (`SlowUploadIntegrationTest` lo prueba con un *socket* en bruto: el hueco vuelve a estar libre al vencer el plazo, y se sirve la subida siguiente), y `read_body 10m` en el `Caddyfile` es un plazo máximo para **toda** la subida (un archivo de 80 MB necesita ~1,1 Mbit/s sostenido para caber), que es lo que corta a un cliente que envía un byte de vez en cuando y nunca se detiene lo bastante para vencer el primer plazo. Límite conocido: el plazo de Tomcat es por lectura, no total; sin el proxy, un cliente que gotea bytes retiene un hueco. La directiva se validó con `caddy validate` en la imagen fijada (2.11.4); `read_body_idle`, que aparece en la documentación actual de Caddy, **no** existe en esa versión y hace fallar la carga del fichero, por eso no se usa.
- *Ajuste:* `PDFVALIDATOR_ANALYSIS_MAX_CONCURRENT` y `PDFVALIDATOR_ANALYSIS_ACQUIRE_TIMEOUT`. Subir `max-concurrent` sube el peor caso: reajusta `-Xmx`, el `tmpfs` y el límite del contenedor.

**Prueba de carga en CI.** El job `docker`, tras la prueba de humo, genera un PDF válido de ~79 MB (`.github/scripts/LargePdfGenerator.java`, sin dependencias, ejecutado con el JDK del *runner*), arranca un contenedor con los mismos límites que producción (`--memory=2g --read-only --tmpfs /tmp:size=256m`) y le envía **5 subidas concurrentes**. Falla si alguna respuesta no es 200 o 503 (un 503 debe llevar el `type` `busy`), si ninguna es 200, si el contenedor se reinicia, lo mata el OOM o aparece `OutOfMemoryError` en los logs. Imprime las muestras de `docker stats` y `memory.peak`. Este último es solo informativo (incluye caché de páginas recuperable y `tmpfs`): el paso falla ante señales reales de OOM (`oom_kill` > 0 en `memory.events`, `OOMKilled=true`, reinicios, contenedor parado o `OutOfMemoryError`). El `WARN` de PDFBox «Using fallback font» inundaba el log; `application.yml` deja el *logger* `org.apache.pdfbox.pdmodel.font` en `ERROR`.

**Endurecimiento.** Usuario no root (`app`, uid 10001); `read_only: true` con `/tmp` como `tmpfs` de 256 MB (única ruta escribible: directorio de trabajo de Tomcat, subidas multiparte y ficheros temporales de PDFBox); `security_opt: no-new-privileges:true`; `cap_drop: [ALL]`; `HEALTHCHECK` con `wget` sobre `/actuator/health` (Docker solo marca el contenedor como `unhealthy`: `restart: unless-stopped` reinicia los que terminan, no los no saludables); Actuator solo expone `health` e `info`.

**Configuración por variables de entorno** (bloque `environment` de `docker-compose.yml`, comentado por defecto): `PDFVALIDATOR_TRUSTSTORE_EXTERNAL_DIR`, `PDFVALIDATOR_REVOCATION_TIMEOUT`, `PDFVALIDATOR_ANALYSIS_MAX_CONCURRENT`, `PDFVALIDATOR_ANALYSIS_ACQUIRE_TIMEOUT`, `SERVER_PORT`. Para añadir raíces de confianza propias, monta un directorio de solo lectura con un certificado por fichero (`volumes: ["./mi-truststore:/truststore:ro"]`) y apunta `PDFVALIDATOR_TRUSTSTORE_EXTERNAL_DIR=/truststore`; se suman a las anclas empaquetadas (§2.7).

**Verificación.** El job `docker` de CI construye la imagen, la arranca con los límites de producción, espera a `/actuator/health` = `UP` (hasta ~90 s), comprueba `GET /` = 200 y ejecuta la prueba de carga anterior; no se publica ninguna imagen. La imagen también se construyó y probó en un VPS real (ver más abajo).

### Despliegue en un VPS

La aplicación está desplegada y accesible en **<https://vps-651608c6.vps.ovh.net/>** (interfaz «Validar»; Swagger UI en `/swagger-ui.html`, salud en `/actuator/health`), con certificado TLS de Let's Encrypt. El puerto 8963 de la aplicación solo escucha en `127.0.0.1`, así que desde fuera únicamente se accede por HTTPS.

| Elemento | Valor |
|---|---|
| Proveedor / plan | OVHcloud VPS-1 (2 vCore, 4 GB, 40 GB NVMe, Gravelines, ~5,43 €/mes con IVA) |
| Sistema | Ubuntu 24.04 LTS, x86_64 |
| Software | Docker (`docker.io`) y Docker Compose v2 desde los paquetes de Ubuntu |
| Firewall | `ufw`: `22/tcp` (SSH), `80/tcp` y `443/tcp` (HTTPS). La aplicación publica `8963` solo en `127.0.0.1` (Docker se salta `ufw`, por eso el cierre se hace en `docker-compose.yml`) |
| HTTPS | Contenedor `caddy:2` fijado por *digest* en `deploy/docker-compose.caddy.yml` (T23; para actualizarlo se cambia el *digest* tras `docker buildx imagetools inspect caddy:2`) (proxy inverso en modo red del host; configuración versionada en `deploy/Caddyfile` y `deploy/docker-compose.caddy.yml`) que obtiene y renueva solo el certificado de Let's Encrypt para `vps-651608c6.vps.ovh.net` y reenvía a `localhost:8963`; redirige HTTP a HTTPS (308), envía `Strict-Transport-Security` (HSTS, 1 año) y admite cuerpos de hasta 82 MB, que debe recibir en menos de 10 minutos (`read_body`, T26b) |
| Acceso SSH | Solo con clave pública; el acceso por contraseña está desactivado |
| Contenedor | `docker compose up -d --build` con el `docker-compose.yml` del repositorio: 2 GB, sistema de ficheros de solo lectura, `/tmp` de 256 MB, `restart: unless-stopped` |

**Cómo se despliega o actualiza** (desde el servidor, con el código del repositorio copiado en `~/pdf-validator`):

```bash
cd ~/pdf-validator
sudo docker compose up -d --build   # reconstruye la imagen y recrea el contenedor
sudo docker compose ps              # debe indicar "healthy"
curl -s http://localhost:8963/actuator/health
```

**Limitaciones conocidas.** Sin login: cualquiera con la URL puede usarla, así que no debe usarse con documentos confidenciales. El acceso HTTP directo al puerto 8963 está cerrado; el proxy Caddy es el único punto de entrada, con TLS y HSTS. La configuración de Caddy está en `deploy/` y se levanta con `docker compose -f deploy/docker-compose.caddy.yml up -d`. Conviene lanzarlo siempre con el mismo nombre de proyecto de Compose (en el VPS, desde `~/https`, con el volumen `https_caddy_data`): con otro nombre se crearía un volumen vacío y Let's Encrypt emitiría un certificado nuevo, con límites de emisión.

**Uso real medido:** PDF de 83 MB y hasta 5 subidas simultáneas sin fallos (pico del contenedor 1013 MiB de 2048); 4 PDFs de 19 a 50 MB subidos a la vez desde el navegador: 871 MiB de pico, sin reinicios ni OOM.

### Ejemplo de uso de la API

```bash
curl -F "file=@/ruta/a/documento.pdf" "http://localhost:8963/api/v1/pdf/analyze?checkRevocation=false"
```

Respuesta (recortada; ver el modelo completo en Swagger UI):

```json
{
  "fileName": "documento.pdf",
  "sizeBytes": 153521,
  "hashes": { "sha256": "ec9493...", "sha512": "02bc1c..." },
  "structure": { "headerVersion": "1.6", "pageCount": 1, "revisionCount": 2, "pagesTruncated": false, "revisionCountLowerBound": false, "pages": [ { "rotation": "DEG_0", "orientation": "PORTRAIT" } ] },
  "security": { "encrypted": false, "permissions": ["PRINT", "MODIFY"] },
  "pdfa": { "status": "NON_COMPLIANT", "declaration": { "declared": false }, "issues": [ { "code": "3.1.3", "message": "...", "messageEs": "..." } ] },
  "signatures": [
    {
      "fieldName": "Signature1",
      "integrity": "INTACT",
      "coverage": { "coversWholeDocument": true },
      "timestamp": { "present": true, "imprintValid": true, "signatureValid": true, "trusted": false, "note": "TSA not trusted: the TSA certificate chain is UNTRUSTED_ROOT at the timestamp time" },
      "chain": [ { "subject": "CN=...", "commonName": "...", "sha256Fingerprint": "78682c..." } ],
      "chainStatus": "UNTRUSTED_ROOT",
      "revocation": { "state": "NOT_CHECKED" },
      "anomaly": null,
      "verdict": "NOT_ADMITTED",
      "verdictReasons": ["VALIDATED_AT_CURRENT_TIME", "CHAIN_UNTRUSTED_ROOT"]
    }
  ],
  "analyzedAt": "2026-09-27T19:59:31.644705600Z",
  "sectionErrors": [],
  "overallVerdict": "NOT_ADMITTED",
  "modifiedAfterLastSignature": false
}
```

`chainStatus` depende de si el certificado firmante llega a una de las raíces configuradas (§2.7); `sectionErrors` solo contiene entradas si una sección falló de forma inesperada (§2.11); `verdict`/`verdictReasons` y `overallVerdict`/`modifiedAfterLastSignature` son el veredicto por firma y a nivel de documento (§2.10).

Con `checkRevocation=true` (§2.8) y una cadena `TRUSTED`, `revocation` se rellena de verdad:

```bash
curl -F "file=@/ruta/a/documento-firmado.pdf" "http://localhost:8963/api/v1/pdf/analyze?checkRevocation=true"
```

```json
"revocation": { "state": "GOOD", "source": "http://ocsp.ejemplo.org/ee", "detail": null }
```

Si la cadena **no** es `TRUSTED` (como en el ejemplo de arriba, `UNTRUSTED_ROOT`), `revocation` se queda en `NOT_CHECKED` con un motivo explícito aunque `checkRevocation=true`: la revocación nunca se consulta para una cadena que no es de confianza (§2.8):

```json
"revocation": { "state": "NOT_CHECKED", "source": null, "detail": "revocation not checked: certificate chain is not trusted" }
```

### Errores de la API

| Estado HTTP | Causa | `type` |
|---|---|---|
| `400` | Falta el campo `file`, o está vacío | `urn:pdfvalidator:error:missing-file` |
| `400` | El contenido no empieza por una cabecera `%PDF-` reconocible (aunque el nombre termine en `.pdf`) | `urn:pdfvalidator:error:not-a-pdf` |
| `400` | Un parámetro de consulta no se puede convertir (p. ej. `checkRevocation=notabool`); el mensaje nombra el parámetro, nunca el valor recibido | `urn:pdfvalidator:error:invalid-parameter` |
| `422` | Documento con cabecera PDF pero corrupto | `urn:pdfvalidator:error:corrupt-pdf` |
| `422` | Documento cifrado con contraseña de usuario no vacía | `urn:pdfvalidator:error:encrypted-pdf` |
| `413` | Fichero superior al límite de subida configurado (80 MB) | `urn:pdfvalidator:error:file-too-large` |
| `503` | Todos los huecos de análisis simultáneo están ocupados tras esperar `acquire-timeout`; lleva la cabecera `Retry-After` (segundos) | `urn:pdfvalidator:error:busy` |
| `500` | Fallo inesperado (sin detalle interno en la respuesta), incluido un fallo leyendo los propios bytes subidos | `urn:pdfvalidator:error:internal-error` |

### Configuración

| Propiedad | Descripción | Por defecto |
|---|---|---|
| `spring.servlet.multipart.max-file-size` / `max-request-size` | Límite de subida | `80MB` / `81MB` |
| `spring.servlet.multipart.file-size-threshold` / `location` | Las subidas se escriben siempre a disco (`/tmp`), nunca al *heap* | `0B` / `${java.io.tmpdir}` |
| `server.tomcat.threads.max` / `accept-count` | Hilos activos y cola de conexiones de Tomcat | `20` / `20` |
| `server.tomcat.connection-timeout` | Espera máxima de Tomcat a los siguientes bytes de una petición (acota una subida detenida, ver «Subidas lentas») | `20s` |
| `pdfvalidator.analysis.max-concurrent` | Análisis simultáneos máximos (*bulkhead*, ver «Límite de análisis simultáneos») | `2` |
| `pdfvalidator.analysis.acquire-timeout` | Espera máxima de un hueco antes de responder `503` | `30s` |
| `pdfvalidator.analysis.max-decoded-stream-size` | Tamaño máximo decodificado de un flujo PDF que no sea imagen; por encima, el PDF/A es `NOT_VALIDATED` (`DOCUMENT_TOO_COMPLEX`, §2.9) | `32MB` |
| `pdfvalidator.analysis.max-decoded-total-size` | Tamaño máximo decodificado de todos los flujos de un PDF juntos (acota la CPU de inflar) | `2GB` |
| `pdfvalidator.analysis.max-pages` | Páginas de las que se devuelve detalle; el resto solo se cuentan (`pagesTruncated`, §2.3) | `1000` |
| `pdfvalidator.analysis.max-revision-markers` | Apariciones de cada palabra clave de revisión (`stream`, `startxref`, `/Prev`) que se recogen; por encima, el número de revisiones es una cota inferior (`revisionCountLowerBound`, §2.3) | `1000000` |
| `pdfvalidator.analysis.max-revisions` | Secciones `xref` que sigue el recorrido de revisiones; por encima, cota inferior | `10000` |
| `pdfvalidator.analysis.max-signature-fields` | Campos de firma que se analizan; si hay más, el documento es `ANALYSIS_INCOMPLETE`, nunca `VALID` (§2.4) | `50` |
| `pdfvalidator.analysis.max-certificates-per-signature` | Certificados tomados de un mismo CMS (§2.5) | `50` |
| `pdfvalidator.analysis.max-chain-length` | Certificados enlazados firmante → raíz al ordenar la cadena (§2.5) | `10` |
| `pdfvalidator.analysis.max-pdfa-issues` | Incidencias PDF/A distintas que conserva el informe; el resto se resume en `TRUNCATED` (§2.9) | `200` |
| `pdfvalidator.truststore.external-dir` | Directorio con certificados adicionales (uno por fichero, PEM o DER), añadidos a las anclas empaquetadas | (ninguno) |
| `pdfvalidator.truststore.pkcs12-path` | Fichero PKCS#12 con certificados de confianza adicionales | (ninguno) |
| `pdfvalidator.truststore.pkcs12-password` | Contraseña del PKCS#12 anterior | (ninguna) |
| `pdfvalidator.revocation.timeout` | Tope por petición OCSP/CRL (DNS + conexión + respuesta) (§2.8) | `2s` |
| `pdfvalidator.revocation.total-timeout` | Un único plazo para toda la comprobación de revocación de una firma (todos los certificados de la ruta, OCSP y CRL); agotado, `UNKNOWN` | `6s` |
| `pdfvalidator.revocation.max-response-bytes` | Tamaño máximo aceptado de una respuesta OCSP/CRL | `10MB` |
| `pdfvalidator.revocation.max-urls-per-method` | URLs AIA (OCSP) / CDP (CRL) que se prueban por certificado, tras quitar repetidas | `3` |
| `pdfvalidator.revocation.max-header-line-bytes` | Longitud máxima de una línea HTTP de la respuesta (estado, cabecera, tamaño de fragmento, *trailer*) | `8KB` |
| `pdfvalidator.revocation.max-headers` | Número máximo de cabeceras (y, aparte, de *trailers* `chunked`) | `100` |
| `pdfvalidator.revocation.max-header-bytes` | Tamaño conjunto máximo de las cabeceras (y de los *trailers*) | `64KB` |
| `management.endpoints.web.exposure.include` | Endpoints de Actuator expuestos | `health,info` |

## 5. Estructura del proyecto

Arquitectura **hexagonal** (puertos y adaptadores): el dominio no depende de Spring, PDFBox ni Bouncy Castle; las librerías se usan solo en los adaptadores de infraestructura. Las reglas de dependencia se comprueban con ArchUnit (§2.12).

```
src/main/java/com/coam/pdfvalidator/
├─ PdfValidatorApplication.java   Punto de entrada Spring Boot
├─ domain/                        Java puro, sin librerías externas
│  ├─ model/                      Records inmutables del informe (páginas, firmas, certificados, SignatureVerdict/OverallVerdict…)
│  ├─ policy/                     SignatureVerdictPolicy (veredicto por firma + documento)
│  ├─ port/                       Interfaces que implementa la infraestructura
│  └─ exception/                  InvalidPdfException, EncryptedPdfException
├─ application/                   AnalyzePdfUseCase (orquestación), AnalysisOptions, NoOpRevocationChecker (implementación de referencia, solo la usa un test)
├─ infrastructure/                Adaptadores PDFBox, Bouncy Castle, PKIX, OCSP/CRL, preflight, web
│  ├─ crypto/                     JcaHashCalculator (SHA-256/SHA-512)
│  ├─ pdfbox/                     PdfBoxDocumentReader (estructura, seguridad, declaración PDF/A), RevisionCounter
│  ├─ bouncycastle/               BcSignatureVerifier (/ByteRange + CMS, cadena de certificados, sellos RFC 3161), DigestAlgorithmOidNormalizer/NormalizingDigestCalculatorProvider
│  ├─ pki/                        PkixCertificateChainValidator, TrustAnchorProvider (cadena de confianza X.509)
│  ├─ revocation/                 CompositeRevocationChecker (OCSP+CRL), OcspClient, CrlClient, RevocationUrlGuard + PinnedHttpClient (guarda SSRF con anclaje de conexión)
│  ├─ preflight/                  PreflightPdfaValidator (validación formal PDF/A-1b)
│  ├─ web/                        CspHeaderFilter (cabecera CSP de la interfaz web), SecurityHeadersFilter (nosniff y no-referrer en todas las respuestas)
│  └─ config/                     AdapterConfiguration (beans de adaptadores), TrustStoreProperties, RevocationProperties, AnalysisProperties, OpenApiConfiguration, WebSecurityHeadersConfiguration
├─ api/                           Controlador REST, DTOs, gestión de errores
│  ├─ concurrency/                AnalysisBulkhead, AnalysisBulkheadFilter (límite de análisis simultáneos), AnalysisBusyException
│  ├─ dto/                        PdfAnalysisReportDto y el resto de DTOs explícitos + PdfAnalysisReportMapper
│  └─ error/                      PdfAnalysisExceptionHandler (ProblemDetail), MaxUploadSizeExceptionHandler, MissingFileException, NotAPdfException
└─ UseCaseConfiguration.java      Cableado de AnalyzePdfUseCase (raíz de composición, fuera de las 4 capas)

src/main/resources/
├─ application.yml                Configuración (límite de subida 80 MB, Actuator, trust store opcional)
├─ truststore/                    Anclas de confianza generadas desde la TSL española (`.crt` en PEM) + index.txt + SOURCES.md (procedencia); no se editan a mano
└─ static/                        Interfaz web "Validar"/"Firmar" -- sin frameworks, sin CDNs
   ├─ index.html                  Página única con ambas pestañas
   ├─ app.js                      Punto de entrada (tema + navegación entre pestañas)
   ├─ dom.js                      Referencias al DOM y utilidades compartidas
   ├─ render.js                   Renderizado del informe de análisis
   ├─ validate.js                 Pantalla "Validar" (analyzeFile/isAnalyzing reutilizados por "Firmar")
   ├─ sign.js                     Pantalla "Firmar" (AutoScript/AutoFirma)
   ├─ styles.css                  Tokens de diseño, tema claro/oscuro
   └─ vendor/autofirma/           AutoScript 1.10.1 sin modificar + licencias + NOTICE.md (§13)

src/test/java/com/coam/pdfvalidator/
├─ fixtures/                      Generación de PDFs de prueba (CA de test, firma, cifrado…), TestHttpServer/TestRevocationResponder (servidor y respuestas OCSP/CRL reales)
├─ spike/                         Prueba de concepto inicial de verificación de firma
├─ tools/tsl/                     Herramienta de mantenimiento TslSync (genera el truststore desde la LOTL/TSL, §4) y sus tests sin red
├─ domain/                        Tests del modelo de dominio
│  └─ policy/                     SignatureVerdictPolicyTest (tabla de decisión completa)
├─ application/                   AnalyzePdfUseCaseTest (fakes) + AnalyzePdfUseCaseIntegrationTest (adaptadores reales)
├─ infrastructure/                Tests de los adaptadores (pdfbox, bouncycastle, crypto, pki, preflight, revocation)
├─ api/                           PdfAnalysisControllerTest (slice), PdfAnalysisEndToEndTest (SpringBootTest + MockMvc), StaticContentSecurityTest (cabecera CSP)
│  ├─ dto/                        PdfAnalysisReportMapperTest
│  └─ error/                      PdfAnalysisExceptionHandlerTest
└─ architecture/                  ArchitectureTest: reglas ArchUnit de la arquitectura hexagonal

odd/tasks/pdf-validator.md        Plan de tareas y evidencias de progreso
.github/workflows/ci.yml          Integración continua
```

## 6. Funcionalidades principales

| Funcionalidad | Estado |
|---|---|
| Verificación de firma CMS y cobertura `/ByteRange` | ✅ |
| Integridad de la firma independiente de la validez del certificado firmante; tolerancia a `digestAlgorithm` no estándar | ✅ |
| Motivo legible siempre presente en resultados no `INTACT` (`anomaly`), nunca el mensaje bruto de una excepción | ✅ |
| Detección de modificación posterior a la firma (actualización incremental) | ✅ |
| Detección de manipulación de bytes firmados | ✅ |
| Firmas múltiples, evaluadas independientemente | ✅ |
| Subfiltros soportados (`adbe.pkcs7.detached`, `ETSI.CAdES.detached`); resto → `UNSUPPORTED` | ✅ |
| `/ByteRange` hostil o inconsistente con `/Contents` → `INVALID_SIGNATURE`, sin excepción | ✅ |
| Hashes SHA-256 / SHA-512 del documento | ✅ |
| Versión (cabecera y catálogo), páginas, rotación, MediaBox/CropBox, orientación | ✅ |
| Número de revisiones (cadena de xref, tolerante a PDF linealizados) | ✅ |
| Cifrado y permisos efectivos, con etiquetas en español en la interfaz (§2.14) | ✅ |
| Incidencias PDF/A con descripción en español y el original en inglés (§2.9) | ✅ |
| Datos del certificado firmante y su cadena (sujeto, emisor, fechas, URLs OCSP/CRL); DN legible y `commonName` propio (§2.5) | ✅ |
| Sello de tiempo RFC 3161 (sello de firma; imprint, firma y confianza de la TSA) | ✅ |
| Cadena de confianza contra almacén configurable (trust store) | ✅ |
| Anclas generadas desde la LOTL de la UE y la TSL española, firmas XML verificadas, con regeneración semanal por PR (T14, §4) | ✅ |
| Revocación OCSP / CRL (opcional, toda la ruta validada menos el ancla, plazo total 6 s, solo para cadena `TRUSTED`, guarda SSRF con anclaje de conexión) | ✅ |
| Declaración XMP `pdfaid` (lectura) | ✅ |
| Validación formal PDF/A-1b (*preflight*) | ✅ |
| Orquestación completa del análisis (`AnalyzePdfUseCase`): hashes, estructura, PDF/A combinado, firmas enriquecidas con cadena/revocación, aislamiento de fallos por sección | ✅ |
| Arquitectura hexagonal comprobada automáticamente (ArchUnit) | ✅ |
| Errores explícitos por sección (`sectionErrors`) cuando una sección falla inesperadamente | ✅ |
| API REST (`POST /api/v1/pdf/analyze`) + Swagger UI + OpenAPI | ✅ |
| Errores RFC 9457 (`ProblemDetail`) con `type` estable por causa | ✅ |
| Actuator (`health`, `info` únicamente) | ✅ |
| Límite de análisis simultáneos (*bulkhead*): `503` `busy` con `Retry-After` al saturarse (§4) | ✅ |
| Veredicto general por firma (✅/⚠️/❌) y a nivel de documento, con motivos explícitos (§2.10) | ✅ |
| Interfaz web con arrastrar y soltar (pantalla **Validar**), tema claro/oscuro, cabecera CSP | ✅ |
| Pantalla **Firmar**: firma PAdES con AutoFirma en el equipo del usuario (la clave privada nunca sale de su equipo) y validación del resultado con un clic | ✅ |
| Imagen Docker multi-etapa y `docker compose` con perfil de memoria acotado y endurecimiento | ✅ (medido en CI y en el VPS) |
| Despliegue en un VPS de bajo coste (OVHcloud, HTTPS) | ✅ <https://vps-651608c6.vps.ovh.net/> (HTTPS con Let's Encrypt) |

## 7. Tests y calidad

El proyecto se desarrolla con **TDD** (primero el test en rojo, luego la implementación en verde y después la refactorización).

Los PDFs de prueba **se generan por código** (`fixtures/TestPdfFactory`): una CA de pruebas en memoria firma documentos, y a partir de ellos se crean variantes manipuladas, con actualización incremental, rotadas, cifradas o corruptas. Así los tests son reproducibles y no dependen de ficheros con datos personales (los dos PDFs reales firmados usados para reproducir casos de FNMT y Camerfirma nunca se incorporaron al repositorio).

**Estado actual:** 528 tests, todos en verde con `./mvnw verify` (que además genera el informe de cobertura de JaCoCo).

| Suite | Qué comprueba |
|---|---|
| `SignatureSpikeTest` | Firma válida, byte manipulado y actualización incremental posterior (prueba de concepto histórica) |
| `TestPdfFactoryTest` | Que cada PDF de prueba tiene la propiedad que dice tener |
| `domain/model/*Test`, `SectionErrorTest`, `DefensiveCopyTest` | Reglas del modelo: normalización de rotación, orientación, validación de `/ByteRange` (incluidos valores negativos y desbordamiento aritmético), hashes, declaración PDF/A, vigencia de certificados, consistencia de `PageInfo`, copias defensivas |
| `PdfaIssueCatalogTest` | Traducción al español por código exacto, respaldo por categoría padre y ausencia de traducción para códigos desconocidos, sintéticos o nulos |
| `JcaHashCalculatorTest` | SHA-256/SHA-512 contra vectores de prueba conocidos |
| `PdfBoxDocumentReaderTest` | Versión (cabecera/catálogo, incluida cabecera ausente), páginas, rotaciones (inválidas, no enteras, heredadas del nodo `/Pages`), orientación, MediaBox/CropBox, cifrado (con y sin contraseña de usuario), entrada corrupta o no-PDF, revisiones, declaración PDF/A presente/ausente/con XMP corrupto |
| `RevisionCounterTest` | Una y varias revisiones encadenadas por `/Prev`, estructura linealizada construida a mano, fichero sin cadena de xref, `/Prev` cíclico, `startxref` fuera de rango, fichero de ~5 MB con 2000 revisiones, coste de escaneo lineal (contando pasos, no tiempo) y concurrencia (16 hilos, sin estado compartido; los tests acotan `invokeAll` con un *timeout* real) |
| `SignatureByteRangeTest` | Hueco de `/ByteRange` frente a la longitud de `/Contents` analizada de forma independiente (escenarios construidos a mano para que ambos discrepen) |
| `BcSignatureVerifierTest` | Documento sin firmar, firma íntegra con cadena y URLs OCSP/CRL, actualización incremental posterior, byte manipulado (con motivo y cadena no vacía), doble firma, `/ByteRange` hostil sin excepción y con `anomaly` no nula, subfiltro no soportado, `ETSI.RFC3161` como no soportado, entrada corrupta, campo de firma que lanza al leerse, sello de tiempo ausente/válido/con imprint incorrecto, certificado firmante caducado en el instante de firma (`INTACT` con nota) y `digestAlgorithm` codificado como OID de firma (con y sin atributos firmados; con manipulación → `INVALID_SIGNATURE`) |
| `TsaCertificateLookupIntegrationTest` | T26a, con certificados reales y un sello pedido con `certReq=false` (sin certificados): TSA en el CMS de la firma → sello de confianza; TSA solo como ancla de confianza → de confianza; certificado con el mismo sujeto y otra clave/serie, o con el mismo emisor y serie pero otro contenido (falla `ESSCertID`) → no se sustituye; TSA en ningún sitio → nota *"TSA certificate not found in the timestamp token"* |
| `SignatureTimestampVerifierTest` | Sin sello → `absent()`, bytes ASN.1 corruptos → inválido con nota, TSA sin `timeStamping` → nota y `tsaTimeStampingEku=false`, cadena de la TSA (TSA primero) y EKU de un sello genuino, el adaptador nunca declara `trusted`, certificado de TSA no mapeable → se conserva el resto del resultado |
| `X509CertificateInfoMapperTest` | Extensiones AIA/CDP mal formadas → sin URLs; DN legible sin `#16<hex>` con `emailAddress`; `commonName` sin escapes RFC 2253, con RDN multivalor, sin CN y con valor no cadena |
| `PkixCertificateChainValidatorTest` | `TRUSTED`, `UNTRUSTED_ROOT`, `INCOMPLETE_CHAIN`, `EXPIRED`, `NOT_CHECKED`; certificado no parseable → `INCOMPLETE_CHAIN`; ancla no autofirmada (caso Camerfirma); cadena con solo el firmante y la CA intermedia como ancla (caso FNMT); `validatedPath` (cadena completa, ancla añadida, certificado ajeno excluido, vacía si no es `TRUSTED`) |
| `TrustAnchorProviderTest` | El almacén empaquetado carga exactamente los ficheros de `truststore/index.txt`, cada uno documentado por su SHA-256 en `SOURCES.md`; contiene AC FNMT Usuarios y AC RAIZ DNIE 2 (aviso si una regeneración los pierde); todas las anclas vigentes y sin caducar en una fecha fija de referencia; directorio externo (PEM/DER, fichero inválido omitido, directorio inexistente) y PKCS#12 |
| `SecureXmlTest`, `TrustedListLoaderTest` | (T14, sin red, listas firmadas en el test con `XMLSignatureFactory`) XML seguro: `DOCTYPE`, expansión de entidades y XXE rechazados sin leer el fichero; lista válida aceptada; contenido manipulado, firmante no fijado, firmante caducado, `NextUpdate` vencido, segunda firma, primera referencia que no cubre el documento, transformación XPath que excluye contenido y lista sin firmar → rechazados |
| `AnchorSelectorTest`, `TslSyncTest`, `HttpsFetcherTest` | (T14) Filtro: `CA/QC` `granted` con `ForeSignatures`, `QCForESig` o sin restricción y `TSA/QTST` `granted` dentro; solo sellos, solo web, `withdrawn`, otros tipos y certificados caducados fuera; deduplicación por SHA-256; nombres de fichero legibles y orden estable; extremo a extremo LOTL → puntero ES → TSL con salida idéntica en dos ejecuciones; TSL firmada por un certificado no anunciado, LOTL no fijada (mensaje para actualizar los pines), puntero no HTTPS o ausente → error; el directorio se sustituye entero y queda intacto si algo falla; solo HTTPS y confianza TLS = `cacerts` + raíz FNMT fijada |
| `PreflightPdfaValidatorTest` | `NON_COMPLIANT` con códigos reales (`3.1.3`, `2.4.3`, `7.1`), `COMPLIANT` con `OutputIntent` sRGB del JDK, corrupto/cifrado → `NOT_VALIDATED`, no-PDF → `InvalidPdfException`, más de 200 incidencias deduplicadas y truncadas |
| `AnalyzePdfUseCaseTest` | Con *fakes* escritos a mano: ensamblado del informe, el `validationTime` (solo un sello de confianza lo mueve: TSA no de confianza, sin EKU, `genTime` futuro con tolerancia de 5 minutos, imprint/firma inválidos, sin cadena de TSA, fallo inesperado; la fecha declarada nunca se usa) y el motivo `VALIDATED_AT_CURRENT_TIME`, revocación desactivada/activada y su puerta de confianza (sin invocar al *checker* si la cadena no es `TRUSTED`; se usa `validatedPath`), PDF/A-2/3 → `NOT_VALIDATED` sin invocar a *preflight*, aislamiento de fallos por sección con `SectionError` y textos fijos, veredicto final, `ANALYSIS_INCOMPLETE`, propagación de `EncryptedPdfException`/`InvalidPdfException`, `analyzedAt` del `Clock` |
| `AnalyzePdfUseCaseIntegrationTest` | Adaptadores reales contra un PDF firmado y sellado en tiempo real por una TSA emitida bajo la raíz de confianza: integridad `INTACT`, cadena `TRUSTED`, sello `trusted`, veredicto `VALID` |
| `TrustedValidationTimeIntegrationTest` | Con certificados reales (firmante caducado hace 2 días): sello falsificado de una TSA propia → `CHAIN_EXPIRED`/`NOT_ADMITTED` (antes `VALID`), fecha declarada nunca usada, sello de una TSA de confianza → `VALID` en su `genTime`, `genTime` futuro y `genTime` anterior a la vigencia de la TSA → no de confianza |
| `ArchitectureTest` | Reglas ArchUnit (§2.12); verificado también introduciendo a propósito una dependencia prohibida |
| `SignatureVerdictPolicyTest` | Cada fila de la tabla de decisión (§2.10), el peor veredicto entre varias firmas, `NO_SIGNATURES`, y la regla de cobertura por firma posterior admitida/no admitida (incluidas tres firmas mezcladas) |
| `RevocationUrlGuardTest` | Solo `http`; cada rango privado/reservado rechazado (incluida IPv4 mapeada en IPv6); resolución única del host y elección de la primera dirección permitida |
| `OcspClientTest`, `CrlClientTest`, `PinnedHttpClientTest` | Contra un servidor HTTP real de test (`TestHttpServer`) con respuestas OCSP/CRL reales y firmadas (`TestRevocationResponder`): `GOOD`, `REVOKED`, estado desconocido, firma inválida, *timeout*, CRL caducada, error HTTP, sin URL, y conexión anclada a la dirección de una única resolución |
| `CompositeRevocationCheckerTest` | Orden OCSP → CRL, sin URLs, emisor `null`, envoltorio de seguridad que registra solo el nombre de la clase de una excepción inesperada, y URLs deduplicadas y limitadas a 3 por método (T21) |
| `CompositeRevocationBudgetTest`, `DeadlineAndLimitsTest`, `RevocationStatusAggregateTest` | T21, con reloj falso (sin dormir segundos): plazo total compartido por todos los certificados de la ruta, intermedia revocada con firmante `GOOD`, firmante revocado sin contactar la CA, ruta toda `GOOD`, intermedia sin URLs, DNS lento acotado, agregación de estados y valores por defecto/validación de las propiedades |
| `PdfAnalysisControllerTest` | *Slice* `@WebMvcTest`: 200 con el informe mapeado, `checkRevocation` reenviado, 400 (ausente, vacío, sin cabecera PDF), 422 (corrupto, cifrado), 500 sin filtrar el mensaje, y `IOException` leyendo la subida → 500 (también a través de la petición completa, sin invocar al caso de uso) |
| `PdfAnalysisExceptionHandlerTest`, `MaxUploadSizeExceptionHandler*Test`, `AnalysisBusyExceptionHandlerTest` | Estado y `type` de cada error; el detalle de un fallo inesperado nunca contiene el mensaje original; `413` real con cuerpo `ProblemDetail` (servidor embebido en `RANDOM_PORT`, límite rebajado a 1 KB, porque `MockMvc` no aplica el límite del contenedor) |
| `SlowUploadIntegrationTest`, `TomcatReadTimeoutConfigurationTest` | T26b: un cliente que deja de enviar el cuerpo libera el hueco al vencer `connection-timeout` (con 60 s la prueba falla), y el `application.yml` entregado fija un plazo ≤ 30 s |
| `AnalysisBulkheadTest`, `AnalysisBulkheadIntegrationTest`, `AnalysisPropertiesTest` | Permisos del *bulkhead*, `503` `busy` con `Retry-After` y `Connection: close` y todas las variantes de URL (`;jsessionid`, `%61nalyze`, barra final, mayúsculas, segmentos de punto) contra el servidor real; las peticiones que no son `multipart/*` (salud, JSON, sin tipo) no compiten por el permiso (T26b) |
| `DtoDefensiveCopyTest` | T24: cada DTO de respuesta toma una copia de sus colecciones al construirse y las expone de solo lectura (una mutación posterior de la lista de origen no lo altera) |
| `PdfAnalysisReportMapperTest` | Mapeo campo a campo de un informe completo y de uno mínimo, veredictos, `NO_SIGNATURES`, y comprobación por reflexión de que `CertificateInfoDto` no expone ningún `byte[]` |
| `PdfAnalysisEndToEndTest` | `@SpringBootTest` + `MockMvc` con adaptadores reales: JSON completo de un PDF firmado y sellado, `/v3/api-docs` correcto y solo `health`/`info` expuestos en Actuator |
| `SecurityHeadersFilterTest`, `SecurityHeadersIntegrationTest` | `X-Content-Type-Options: nosniff` y `Referrer-Policy: no-referrer` en interfaz, API, errores y Actuator |
| `StaticContentSecurityTest`, `CspHeaderFilterTest` | Cabecera CSP exacta en `/`, `/index.html`, `/app.js`, `/styles.css` (con y sin *context path*); ausente en `/v3/api-docs`, `/api/v1/pdf/analyze` y `/vendor/autofirma/autoscript.js`; coincidencia exacta de ruta (nunca por subcadena); `charset=UTF-8` en las rutas estáticas y ningún *charset* forzado en el JSON de error |

### Herramientas de calidad de código

`./mvnw verify` ejecuta, además de los tests, las herramientas siguientes, y **todas son una puerta** (T24): JaCoCo falla por debajo de su umbral, SpotBugs falla ante cualquier aviso de nivel *Medium* o superior que no esté en la lista de exclusiones justificadas, PMD falla ante infracciones de prioridad 1 y 2 (las de prioridad 3, casi todas de complejidad, solo se informan) y CPD falla ante cualquier duplicado de 100 tokens o más. Duración de `verify`: ~1 min en total.

| Herramienta | Qué comprueba | Informe | Resultado actual (2026-10-01) |
|---|---|---|---|
| **JaCoCo** (`check`) | Cobertura mínima del conjunto («trinquete»: si baja, falla la compilación) | `target/site/jacoco/index.html` | Líneas 90,91 % y ramas 79,87 % medidas; umbrales **88 %** y **75 %** (propiedades `jacoco.min.line` / `jacoco.min.branch` del `pom.xml`) |
| **SpotBugs + FindSecBugs** (puerta) | Patrones de error y de inseguridad (umbral *Medium*, esfuerzo *Max*); `failOnError=true` con las exclusiones de `config/spotbugs/exclude.xml` | `target/spotbugsXml.xml` | **0 avisos** (26 antes de T24: 20 `EI_EXPOSE_REP/REP2` corregidos con copias defensivas en los DTO, 1 posible NPE corregido, `DMI_RANDOM_USED_ONLY_ONCE` corregido con un `SecureRandom` compartido, 2 `CT_CONSTRUCTOR_THROW` corregidos haciendo `final` la clase, y 2 excluidos con justificación, ver abajo) |
| **PMD** (puerta en prioridad 1-2) | Buenas prácticas y complejidad (`config/pmd/ruleset.xml`: *quickstart* más complejidad ciclomática/cognitiva/NPath, `GodClass`, `NcssCount`); `failurePriority=2` | `target/pmd.xml` | 0 infracciones de prioridad 1-2 y **24 de prioridad 3, todas de complejidad** y solo informadas: `CyclomaticComplexity` (13), `GodClass` (4), `CognitiveComplexity` (4), `NPathComplexity` (2), `ExcessiveParameterList` (1). Eran 52 antes de T24 |
| **CPD** (puerta) | Código duplicado (mínimo 100 tokens); falla ante cualquier duplicado | `target/cpd.xml` | **0 duplicados** (2 antes de T24: el bucle «probar cada URL» de `OcspClient`/`CrlClient` y la lectura de la declaración XMP de `PdfBoxDocumentReader`/`PreflightPdfaValidator`, ahora compartidos) |
| **PIT** | Pruebas de mutación: ¿los tests detectan cambios en el código? | `target/pit-reports/index.html` | 74 % de mutantes eliminados (937 generados), fuerza de los tests 82 %, cobertura de líneas 89 %; ~6 min |
| **CodeQL** | Análisis de seguridad de GitHub (`.github/workflows/codeql.yml`, Java, JDK 25, en *push*/*pull request* a `master` y cada semana) | pestaña *Security* de GitHub | Pendiente de la primera ejecución en GitHub |

Comandos:

```bash
./mvnw verify                                                           # tests + JaCoCo (con umbral) + SpotBugs + PMD/CPD
./mvnw -Pmutation test-compile org.pitest:pitest-maven:mutationCoverage  # PIT, ~6 min
```

**Qué se corrigió y qué se excluyó (T24).** Se corrigió lo que era un defecto real: los DTO copian sus colecciones (sin cambiar el JSON; el conjunto de permisos conserva su orden con un `LinkedHashSet`, porque `Set.copyOf` lo aleatoriza por ejecución), una subida sin nombre de fichero ya no produce un 500 (el informe lleva el nombre vacío), los nonce OCSP salen de un único `SecureRandom` estático, las excepciones relanzadas conservan su causa (sin volcar nunca el texto de la biblioteca al informe, solo al registro), y los métodos que devolvían `null` en lugar de una colección vacía ya no lo hacen. Se excluyeron solo dos falsos positivos de SpotBugs, cada uno con su razón en `config/spotbugs/exclude.xml` y con una coincidencia por clase, método y patrón:

- `UNENCRYPTED_SOCKET` en `PinnedHttpClient.send`: OCSP (RFC 6960) y CRL (RFC 5280) se publican por `http://` por diseño; la respuesta va firmada y se verifica, así que TLS no añadiría integridad, y el riesgo real (SSRF) lo cubren `RevocationUrlGuard` y la conexión anclada a la dirección resuelta una sola vez.
- `UNSAFE_HASH_EQUALS` en `CmsSignatureVerification.verifyWithMislabeledDigestAlgorithm`: compara el resumen público del atributo firmado `message-digest`; no hay secreto cuyo tiempo de comparación pueda filtrarse.

En PMD se usa `@SuppressWarnings("PMD.CloseResource")` (con comentario) en tres métodos donde el flujo pertenece a otro objeto que lo cierra (`PDDocument`, `Socket`) o se reasigna por etapas con cierre en `finally`, y `ForLoopCanBeForeach` en un bucle cuyo índice solo acota la profundidad de la cadena. Las reglas de complejidad no se refactorizaron en bloque: quedan informadas porque reducirlas exigiría reescribir el verificador CMS, el cliente HTTP anclado y la guardia de URL, que ya están cubiertos por tests de comportamiento pero no merecen un cambio de esa envergadura sin un defecto detrás.

**Comprobación de que las puertas funcionan.** Se introdujo a propósito una infracción trivial por herramienta y se comprobó que `verify` fallaba: una clase con `a == new String("x")` → SpotBugs `ES_COMPARING_PARAMETER_STRING_WITH_EQ` (*Medium*) y `BUILD FAILURE`; un método que devuelve `null` en lugar de una lista → PMD `ReturnEmptyCollectionRatherThanNull` (prioridad 1) y `BUILD FAILURE`; una copia de `UrlFallback` → CPD «found 1 duplication» y `BUILD FAILURE`. Las tres clases se retiraron sin commitearlas.

El job `build` de CI sube como artefacto `quality-reports` los informes de SpotBugs, PMD, CPD y JaCoCo. Las clases con peor puntuación de mutación son `AdapterConfiguration` (0 %, sin tests directos), `OcspClient` (43 %), `CrlClient` (52 %), `PreflightPdfaValidator` (59 %) y `PinnedHttpClient` (62 %).

PDFs de prueba disponibles en `TestPdfFactory`: sin firmar, multipágina, firmado, firmado y después modificado, firmado y manipulado, doble firma, firmado con sello de tiempo válido o con imprint incorrecto, páginas rotadas (incluidos valores como `-90` o `450` y una rotación heredada), apaisado, con CropBox, cifrado con permisos restringidos (AES-256), cifrado con contraseña de usuario vacía, corrupto, no-PDF, con declaración PDF/A, firmado por un certificado ya caducado en el instante de firma y firmado con `digestAlgorithm` codificado como OID de firma. Las TSA de pruebas son identidades en memoria con el uso extendido `id-kp-timeStamping`: `TestPki.issueTsaIdentity` cuelga de una raíz propia que nadie reconoce (la TSA de un atacante) y `TestPki.issueTsaIdentityUnder` la emite bajo la raíz del firmante (una TSA de confianza); `TestPki.issueExpiredSigner` crea un firmante caducado hace 2 días con una raíz vigente hace 500 días, y `TestPdfSigner` permite fijar el `genTime` del sello y la fecha declarada.

## 8. Usuario y contraseña de prueba

**No aplica.** La aplicación no tiene login (tampoco la instancia desplegada): es un servicio sin estado que no guarda documentos ni datos de usuario. Basta con abrir la URL de la demo.

## 9. Presentación

Diapositivas (17, con capturas reales de las pantallas «Validar» y «Firmar», de las páginas agrupadas y los recortes, y un resumen de la auditoría de seguridad):

- PDF: [`docs/PDF-Inspector-TFM.pdf`](docs/PDF-Inspector-TFM.pdf) — <https://github.com/avalinani/verificador/blob/master/docs/PDF-Inspector-TFM.pdf>
- PowerPoint (editable): [`docs/PDF-Inspector-TFM.pptx`](docs/PDF-Inspector-TFM.pptx)

Demostración en vivo: <https://vps-651608c6.vps.ovh.net/>

## 10. Decisiones técnicas

**Plataforma y despliegue**

- **Perfil de recursos de 2 GB y subidas de 80 MB en lugar de la VM de 512 MB – 1 GB del enunciado.** El proyecto se diseñó y se midió primero para 512 MB con PDF de hasta 20 MB y un análisis a la vez (5 × 200 en CI, sin OOM). Tras desplegarlo, se decidió admitir PDF reales de hasta 80 MB (planos y documentación de visado), que no caben con margen en 512 MB: PDFBox y *preflight* multiplican la memoria del documento. Con 2 GB, 2 análisis simultáneos y 30 s de espera, 5 subidas de 83 MB a la vez dieron 5 × 200 y un pico de 1013 MiB. El perfil de 512 MB sigue siendo posible sobrescribiendo `JAVA_TOOL_OPTIONS`, `mem_limit`, el `tmpfs` y el límite de subida (§4). Mediciones del perfil anterior (512 MB, PDF sintético de 19,9 MB, 5 peticiones simultáneas): con `max-concurrent=2`, `memory.peak` 502,3 de 512 MiB (margen de ~10 MB); con `max-concurrent=1`, 5 × 200, pico muestreado 287,6 MiB, `memory.peak` 474,9 de 512 MiB, 0 `oom_kill` y 0 reinicios.
- **Spring Boot 4.1.1 en lugar de 3.x.** El documento del TFM recomendaba Spring Boot 3.x, pero el soporte OSS de la rama 3.5 (la última 3.x) terminó el 30/06/2026. La 4.1 tiene soporte hasta el 31/07/2027. En Boot 4 el starter web pasa a llamarse `spring-boot-starter-webmvc`.
- **Java 25 en lugar de 21.** Java 25 es la LTS más reciente (soporte hasta 2031) y está dentro del rango soportado por Spring Boot 4.1 (17–26). Aporta mejoras útiles en una VM de poca memoria, como las *compact object headers*. Se descartó Java 27 porque no es LTS y queda fuera del rango soportado.
- **OpenLogic en local, Temurin en CI y contenedor.** Las dos distribuciones son OpenJDK con la misma licencia (GPLv2 + Classpath Exception) y la misma política criptográfica (`crypto.policy=unlimited`); no hay diferencias funcionales para el proyecto.
- **Límite de concurrencia como filtro de servlet (*bulkhead*), no en el controlador.** Spring lee la subida multiparte antes de invocar al controlador; el filtro toma el permiso antes y se aplica a toda petición `multipart/*` en cualquier ruta, porque comparar la URL exacta se podía evadir con variantes de ruta (`;jsessionid=x`, `%61nalyze`). Se prefirió limitar la concurrencia a usar ficheros temporales de PDFBox para acotar la memoria (§4).

**Arquitectura y errores**

- **Arquitectura hexagonal comprobada con ArchUnit.** El cableado de `AnalyzePdfUseCase` vive fuera de las cuatro capas, en `com.coam.pdfvalidator.UseCaseConfiguration` (la "raíz de composición"), porque `infrastructure` no puede depender de `application` y ese `@Bean` depende de ambas (§2.12, §2.13).
- **DTOs explícitos, nunca el dominio serializado directamente; nunca la codificación DER de un certificado.** Los certificados se identifican por una huella SHA-256.
- **`@RestControllerAdvice` acotado a `PdfAnalysisController`, más un *advice* propio para el `413`.** Sin `assignableTypes`, un `@ExceptionHandler(Exception.class)` afectaría a toda la aplicación y convertiría un `404` legítimo de Actuator en `500`. Pero `MaxUploadSizeExceededException` se lanza antes de resolver ningún *handler*, así que necesita un segundo *advice* sin acotar que solo reacciona a esa excepción (§2.13).
- **Ningún mensaje de excepción llega al cliente.** `SectionError`, las notas de anomalía, las notas de sello de tiempo, las incidencias PDF/A y los errores `500` usan textos fijos y no sensibles; el detalle real se registra por log (§2.11, §2.13). Revisado en T23: los últimos puntos que concatenaban una excepción (sello de tiempo y validador PDF/A) ya no lo hacen. Se dejan a propósito los rechazos de URL de revocación (`CRL URL rejected: ...`, `OCSP URL rejected: ...`): los textos de `RevocationUrlRejectedException` son fijos y nunca incluyen el host ni la URL (un test lo fija), y la URL ya forma parte del informe. `CompositeRevocationChecker` solo registra por log el nombre de la clase; al cliente le llega siempre *"... check failed (unexpected error)".
- **Documento cifrado (contraseña no vacía) o corrupto: se propaga, no se degrada a un informe parcial.** `AnalyzePdfUseCase` deja salir `EncryptedPdfException`/`InvalidPdfException` y la capa REST las mapea a `422`.
- **Un resultado vacío nunca es indistinguible de un fallo silencioso.** `sectionErrors()` en el informe y `ANALYSIS_INCOMPLETE` en el veredicto evitan confundir una lista de firmas vacía por fallo con "documento sin firmar".

**Firmas y certificados**

- **Integridad criptográfica y validez del certificado son dos hechos separados.** La firma se verifica con la clave pública del firmante (nunca con el certificado completo) para que Bouncy Castle no acople la firma a la vigencia del certificado en el instante de firma; esa vigencia se comprueba aparte y se informa como nota de anomalía (§2.4).
- **`digestAlgorithm` mal etiquetado: normalización acotada y verificación directa.** Solo se normalizan OIDs de firma que nombran exactamente un resumen (RSA PKCS#1 v1.5, ECDSA, DSA clásico); `id-RSASSA-PSS` y `rsaEncryption` a secas no se normalizan porque no nombran un resumen sin ambigüedad. La verificación no pasa por `SignerInformation#verify(...)`: el `translateBrokenRSAPkcs7` de Bouncy Castle 1.86 solo corrige la variante SHA-1, y para SHA-256 reconstruye un `DigestInfo` con el OID equivocado y devuelve `false` en silencio. Se construye el `ContentVerifier` directamente con el OID tal cual (§2.4).
- **La cadena de certificados se extrae siempre que el CMS se pudo parsear**, aunque la verificación falle; todo resultado no `INTACT` lleva un motivo legible.
- **`ETSI.RFC3161` (sello de tiempo de *documento*) se mantiene `UNSUPPORTED`.** Verificarlo exigiría un camino distinto (interpretar el CMS como `TimeStampToken`, sin cadena de firmante habitual), y el sello de **firma** (§2.6) ya cubre lo que pide el TFM: demostrar cuándo existía una firma. Es una decisión consciente, no una omisión.
- **Nombres de certificado con Bouncy Castle `X500Name` + `BCStyle` y `commonName` en el dominio.** El RFC 2253 de la JDK vuelca `emailAddress` como `#16<hex>`; y como `api` no puede depender de `infrastructure`, el CN se extrae en el adaptador y se expone desde `CertificateInfo` (§2.5).
- **Anclas de confianza no autofirmadas.** Una Lista de Confianza de la UE publica la CA emisora cualificada (y la unidad TSA) sin su raíz, y un PDF real firmado con FNMT no trae la CA intermedia en el CMS; el `CertPathBuilder` de la JDK acepta como ancla cualquier certificado configurado (§2.7).
- **Anclas generadas desde las Listas de Confianza oficiales, con una herramienta de mantenimiento y no en el servidor (T14).** Sustituye a la curación manual de 9 anclas. Se descartó que el servidor descargara la TSL en ejecución: añadiría tráfico saliente, dependencia de red al arrancar y una caché en un contenedor de solo lectura. En su lugar, `TslSync` (§4) verifica la LOTL contra los firmantes anunciados en el Diario Oficial, la TSL española contra los firmantes que anuncia la LOTL ya verificada, y regenera el almacén empaquetado; una tarea semanal propone el cambio como PR, que revisa una persona. Vive en `src/test/java` porque así se prueba con el `verify` normal y nunca llega al jar, sin un módulo Maven aparte; a cambio, SpotBugs, PMD y JaCoCo (que solo analizan `src/main`) no la cubren. La verificación usa solo `javax.xml.crypto.dsig` de la JDK (sin la dependencia DSS).
- **Qué servicios son anclas.** `CA/QC` `granted` para firma electrónica (`ForeSignatures`, `QCForESig` o sin restricción de uso) y `TSA/QTST` `granted`; se excluyen las CA solo de sellos o de autenticación web (p. ej. AC CAMERFIRMA FOR LEGAL PERSONS - 2016 y AC Componentes Informáticos, que estaban en el almacén manual). Un sello electrónico emitido por ellas deja de llegar a `TRUSTED` salvo que se añada como ancla externa (§2.7).
- **PDF/A-1b únicamente.** *Preflight* solo valida PDF/A-1b. Para PDF/A-2/3 se informa la declaración XMP y `NOT_VALIDATED` (`PDFA_PART_NOT_SUPPORTED`), sin validar formalmente.
- **(✅ T14, hecho) Anclas generadas desde las Listas de Confianza.** La mejora futura que figuraba aquí (cargar las anclas desde la TSL española a través de la LOTL de la UE) está implementada como herramienta de mantenimiento y tarea semanal de CI, no como descarga en el servidor: ver §2.7 y §4.

**Revocación y red**

- **Revocación opcional y acotada.** Las consultas OCSP/CRL dependen de la red, así que se activan con un parámetro, tienen un *timeout* de 2 s y, si fallan, el resultado es `UNKNOWN` sin bloquear el resto del análisis (§2.8).
- **La revocación solo se comprueba para una cadena `TRUSTED`, y con los certificados de `validatedPath`.** Las URLs OCSP/CRL viven en extensiones de un certificado potencialmente hostil; comprobarlas incondicionalmente sería un vector de SSRF con un certificado autofirmado a mano. Y el CMS (controlado por quien sube el PDF) podría embeber un certificado adicional ajeno a la ruta real: `validatedPath` devuelve exactamente lo que PKIX usó.
- **`PinnedHttpClient`: un cliente HTTP/1.1 propio sobre `Socket`, no `java.net.http.HttpClient`.** Este último resuelve el host por su cuenta al conectar, tras la resolución de la guarda; dos resoluciones que un DNS hostil puede responder distinto (*DNS rebinding*). Se resuelve una vez y se ancla la conexión a esa dirección.
- **Solo `http`, nunca `https`, para OCSP/CRL.** Anclar TLS a una IP concreta preservando SNI y verificación de nombre es posible pero desproporcionado para una función opcional; se rechaza explícitamente en vez de una implementación TLS parcial. La confianza la aporta la respuesta firmada, no el transporte; FNMT y Camerfirma publican por `http://`.
- **Servidor HTTP de test sobre `com.sun.net.httpserver.HttpServer` en vez de WireMock**, para evitar un posible conflicto de classpath con el Jetty de Spring Boot 4.1.1.

**Veredicto e interfaz**

- **Veredicto como política de dominio pura** (`domain/policy/SignatureVerdictPolicy`): qué combinación de integridad/cadena/revocación cuenta como "válida" es una regla de negocio, testeable sin *fakes*. `overallVerdict()` y `modifiedAfterLastSignature()` son métodos calculados, no componentes del *record*, para que no puedan desincronizarse con las firmas.
- **`UNSUPPORTED` es `NOT_ADMITTED`, no `INVALID`; `REVOKED` es siempre `INVALID`** (con la salvedad de que la revocación consultada es la actual, §2.10).
- **Momento de validación: solo un sello de confianza, si no «hoy» (T19; sustituye a la precedencia anterior).** La regla original era: `genTime` del sello si sus firmas verifican → fecha declarada por el firmante → reloj. La auditoría del código encontró dos agujeros: (1) el sello se verificaba contra el certificado que el propio sello lleva, sin comprobar que la TSA llegara a un ancla, de modo que quien tuviera la clave de un certificado legítimo ya caducado podía firmar hoy, fabricar un sello con una TSA propia y cualquier `genTime`, y obtener `TRUSTED`/`VALID`; (2) sin sello se usaba la fecha declarada por el firmante, que puede escribir lo que quiera. Decisión del usuario (estilo ETSI, opción 1): la cadena del firmante se valida en el `genTime` **solo si el sello es de confianza** (imprint, firma de la TSA, `id-kp-timeStamping`, cadena de la TSA hasta un ancla en ese `genTime`, `genTime` no futuro con 5 minutos de tolerancia); en cualquier otro caso, a fecha de hoy. La fecha declarada queda solo informativa. Consecuencia aceptada: una firma sin sello de confianza cuyo certificado caducó después pasa a `NOT_ADMITTED` (`CHAIN_EXPIRED`), con el motivo `VALIDATED_AT_CURRENT_TIME` explicándolo. La confianza se decide en la capa de aplicación con el puerto `CertificateChainValidator` (sin duplicar PKIX ni meter Bouncy Castle en el dominio). La revocación del certificado de la TSA queda fuera de alcance.
- **"Cubierta por una firma posterior" exige que las firmas posteriores estén admitidas (`VALID`), no solo `INTACT`**, y es una comprobación estructural, no una comparación de contenido entre revisiones. Con solo `INTACT`, un atacante podía modificar un documento firmado por una entidad de confianza y volver a firmarlo con un certificado propio sin que la firma original dejara de parecer `VALID` (§2.10).
- **Límites de recursos ante PDF hostiles: se trunca y se dice, no se falla (T20).** Cada límite (`pdfvalidator.analysis.max-*`, tabla de §4) devuelve `200` con un indicador explícito y estable (`pagesTruncated`, `revisionCountLowerBound`, incidencia PDF/A `TRUNCATED`, `sectionErrors` de `SIGNATURES`), nunca una excepción. El único que puede cambiar un veredicto es el de campos de firma: si queda alguno sin analizar el documento es `ANALYSIS_INCOMPLETE`, nunca `VALID` (§2.4). Los valores por defecto no se han medido contra PDF reales grandes: son cotas generosas para un documento legítimo (1 000 páginas con detalle, 50 firmas, 50 certificados por firma, 10 de cadena, 200 incidencias PDF/A, 1 000 000 de marcadores de revisión) y se ajustan por configuración. Comprobación de extremo a extremo: un fichero de 20 MB con 2 000 000 de `startxref` se analiza en 0,6 s y uno con 200 campos de firma en 1,0 s, ambos con `200` y la JVM sana (`-Xmx1024m`).
- **Cabecera CSP con un filtro Spring acotado por ruta exacta**, no un `url-pattern` de Servlet (`"/"` coincide con toda petición) ni una etiqueta `<meta>` (que no soporta `frame-ancestors`). Compara la ruta relativa al *context path* (`getRequestURI()` ya lo incluye) y no afecta a Swagger UI, Actuator ni a la API.
- **`charset=UTF-8` desde el mismo filtro y no con `spring.servlet.encoding.force`.** La propiedad global forzaría el *charset* también en el JSON de la API, y el contrato es `Content-Type: application/json` sin parámetro.
- **CSS: una única regla `[hidden] { display: none !important; }`.** Una regla de igual especificidad que la del navegador para `[hidden]`, si va después en la cascada, gana; una regla temprana con `!important` evita acordarse de añadirlo a cada selector.
- **`setForceWSMode(true)` de AutoScript NO se activa, a pesar de su nombre.** Leyendo el código de AutoScript 1.10.1 (`cargarAppAfirma`), ese flag fuerza el transporte de **servidor intermedio** (con *servlets* propios de guardado/recuperación), no el modo WebSocket. Sin él, cualquier navegador de escritorio con WebSocket habla directamente con AutoFirma por `wss://127.0.0.1:<puerto>`.
- **AutoScript se incluye sin modificar, como componente de terceros independiente** (razonamiento de licencias en §13), y su diálogo propio se desactiva (`SupportDialog.enableSupportDialog(false)`) en vez de relajar la CSP: inyecta un `<style>` en línea, y añadir `'unsafe-inline'` a `style-src` por un componente que además duplicaría la interfaz de espera/cancelar no compensa.
- **CSP ampliada con lo estrictamente necesario, nunca `'unsafe-eval'`/`'unsafe-inline'` para scripts.** AutoScript no usa `eval()`/`Function()` ni genera `<script>` en línea. Solo hicieron falta `connect-src wss://127.0.0.1:* https://127.0.0.1:*` (cliente WebSocket y su alternativa de compatibilidad, a un puerto local dinámico) y `frame-src 'self' afirma:` (el `<iframe>` oculto que Firefox/Safari usan para lanzar AutoFirma).
- **Página única con pestañas, no un `firmar.html` separado**, para reutilizar cabecera, tema, filtro CSP y `render.js` para «Validar este PDF». `switchTab` vive en `dom.js`, el módulo hoja del que dependen `app.js` y `sign.js`, para evitar un ciclo de importación entre ES *modules*.

- **Dependencias parcheadas por encima de lo que gestiona Spring Boot (T18b).** Spring Boot 4.1.1, la última versión, gestiona Tomcat 11.0.24 y Jackson 3.1.5 / 2.21.5, que OSV.dev marca como vulnerables: Tomcat (CVE-2026-65905, CVE-2026-65182, CVE-2026-68525, corregidas en 11.0.25), `tools.jackson.core:jackson-databind` (CVE-2026-68497, CVE-2026-83557, CVE-2026-19032, corregidas en 3.1.6) y `com.fasterxml.jackson.core:jackson-databind` 2.21.5 (corregida en 2.21.6; llega por springdoc/swagger-core). El `pom.xml` sobrescribe las propiedades de versión del BOM de Spring Boot (`tomcat.version=11.0.26`, `jackson-bom.version=3.1.7`, `jackson-2-bom.version=2.21.6`) y `PatchedDependenciesTest` falla si una versión resuelta baja de la primera corregida. Consultadas las 114 dependencias resueltas contra OSV.dev el 2026-09-30, ninguna tiene vulnerabilidades conocidas. Cuando Spring Boot gestione versiones parcheadas, cada sobrescritura se retira.
- **Swagger UI y `/v3/api-docs` siguen siendo públicos: riesgo aceptado (T23).** Es la documentación de la API que usan los evaluadores, no expone nada sensible (solo el contrato: rutas, parámetros y esquemas de respuesta, no datos ni configuración), y ya recibe las cabeceras de seguridad globales (`SecurityHeadersFilter`) y los mismos límites de subida y de concurrencia que la API. Si algún día hiciera falta cerrarlos: `springdoc.swagger-ui.enabled=false` (interfaz) y `springdoc.api-docs.enabled=false` (documento OpenAPI), o sus equivalentes de entorno `SPRINGDOC_SWAGGER_UI_ENABLED` / `SPRINGDOC_API_DOCS_ENABLED`; ambas propiedades existen en los metadatos de configuración de springdoc 3.1.1. Al desactivar `api-docs`, la interfaz deja de tener contrato que mostrar. Este proyecto no las desactiva ni lo comprueba con un test.

## 11. Historial de cambios

| Fecha | Cambio |
|---|---|
| 2026-09-26 | Esqueleto Maven + Spring Boot, CI y prueba de concepto de verificación de firma (T01). |
| 2026-09-26 | Paso a Spring Boot 4.1.1 y Java 25 LTS. |
| 2026-09-26 | Generador de PDFs de prueba, modelo de dominio inmutable, puertos y excepciones (T02). |
| 2026-09-27 | Endurecimiento del modelo de dominio frente a `/ByteRange` y rotaciones hostiles (T02b). Calculadora de hashes y lector de estructura/seguridad/PDF/A sobre PDFBox (T03). |
| 2026-09-27 | Conteo de revisiones por cadena de xref (tolerante a PDF linealizados), rotaciones no enteras/no numéricas correctamente marcadas inválidas, cabecera `%PDF-` ausente ya no aborta el análisis (T03b). Verificador de firmas Bouncy Castle: `/ByteRange` + CMS, firmas múltiples independientes, subfiltros soportados/no soportados, extracción de la cadena de certificados con URLs OCSP/CRL (T04). |
| 2026-09-27 | Endurecimiento del verificador de firmas (T04b): comprobación del hueco de `/ByteRange` frente a la longitud de `/Contents` analizada de forma independiente (la anterior era una tautología autorreferencial), conteo de revisiones lineal/acotado en vez de cuadrático (con vuelta a `%%EOF` ante un `startxref` fuera de rango), ningún campo de firma hostil puede ya escapar del guardado por-campo, y un fallo al mapear un certificado ya no degrada una firma criptográficamente válida a `INVALID_SIGNATURE` (se informa con una nota de anomalía). Verificación de sellos de tiempo RFC 3161 sobre el valor de la firma: imprint, firma de la TSA y uso extendido de clave `timeStamping` (T05); los sellos de tiempo de *documento* (`ETSI.RFC3161`) siguen `UNSUPPORTED`, por decisión documentada. |
| 2026-09-27 | Repositorio publicado en GitHub (fusión del commit inicial con la licencia GPL-3.0). CI de GitHub Actions en verde con Temurin 25. |
| 2026-09-27 | (T05b) Un fallo al mapear el certificado de la TSA ya no descarta el resto del resultado del sello de tiempo; camino de resiliencia del mapeador de certificados probado directamente; test de rendimiento del contador de revisiones sustituido por una comprobación determinista (sin reloj de pared). (T06) Validación de cadena de confianza X.509 con la implementación PKIX de la JDK (`PkixCertificateChainValidator`), contra un almacén de confianza configurable (`TrustAnchorProvider`) con seis raíces españolas empaquetadas y verificadas de forma independiente (§2.7). |
| 2026-09-27 | (T06b) `RevisionCounter` ya no guarda su diagnóstico de escaneo en un campo `static` (condición de carrera bajo concurrencia); `PkixCertificateChainValidator` informa un certificado no parseable como `INCOMPLETE_CHAIN` en vez de lanzar excepción; `TrustAnchorProvider` omite (sin abortar) un fichero inválido en el directorio externo, con tests nuevos para directorio externo y PKCS#12; la comprobación de vigencia de las raíces empaquetadas ya usa una fecha de referencia fija en vez de `Instant.now()` (§2.7). (T07) Validación formal PDF/A-1b con el módulo *preflight* de Apache PDFBox (`PreflightPdfaValidator`): `COMPLIANT`/`NON_COMPLIANT` con incidencias deduplicadas y acotadas, `NOT_VALIDATED` para cifrado o fallos internos sin lanzar excepción, `InvalidPdfException` solo para entradas sin cabecera `%PDF-` reconocible; documenta por qué solo se valida formalmente PDF/A-1b (§2.9). |
| 2026-09-27 | (T07b) El fixture PDF/A-1b conforme usa ahora el perfil sRGB del propio JDK en vez del fichero de Windows, así que su test ya no se salta en CI; el sondeo previo de cifrado en `PreflightPdfaValidator` también captura una `RuntimeException` inesperada; nuevos tests para la rama de documento cifrado con contraseña vacía y para la truncación/deduplicación de incidencias a 200; `TrustAnchorProvider` ya no propaga una excepción si el directorio externo no se puede ni listar; el test de concurrencia de `RevisionCounter` se reforzó para detectar específicamente un contador de pasos compartido reintroducido (§2.9). (T08) `AnalyzePdfUseCase`: orquesta todos los puertos del dominio en un único análisis, decide `validationTime` para la cadena de confianza (sello de tiempo válido → fecha de firma auto-declarada → reloj), combina la validación PDF/A-1b formal con la declaración XMP real, resuelve el flag de revocación (con `NoOpRevocationChecker` como implementación provisional hasta T10) y aísla el fallo de una sección para no perder el resto del informe; reglas de arquitectura hexagonal comprobadas automáticamente con ArchUnit (§2.11, §2.12). |
| 2026-09-27 | (T08b) `PdfAnalysisReport` gana `sectionErrors()`: un fallo inesperado de `SignatureVerifier`/`PdfaConformanceValidator` ya no es indistinguible de un resultado vacío legítimo. La validación PDF/A ahora comprueba la declaración XMP antes de invocar el validador formal (y lo omite del todo para PDF/A-2/3, evitando un parseo de más). Corregido el *timeout* ineficaz de los tests de concurrencia de `RevisionCounter` (acotando `executor.invokeAll(...)` en vez de solo el `future.get(...)` posterior). |
| 2026-09-27 | (T09) API REST: `POST /api/v1/pdf/analyze` (multipart, `checkRevocation` opcional), DTOs explícitos sin exponer tipos de dominio ni bytes DER de certificados, errores RFC 9457 (`ProblemDetail`) con `type` estable por causa, Swagger UI/OpenAPI, Actuator limitado a `health`/`info`. Cableado de adaptadores con Spring (`infrastructure/config`) y del caso de uso en la raíz de composición (`UseCaseConfiguration`), fuera de las cuatro capas de la arquitectura. Corregido en local un `@RestControllerAdvice` sin acotar que convertía en `500` los `404` legítimos de Actuator/recursos estáticos (§2.13). |
| 2026-09-27 | (T09c) Corregidos dos falsos negativos reales, encontrados y verificados analizando dos PDFs firmados reales (nunca incorporados al repositorio, ni siquiera sus bytes derivados): un certificado firmante ya caducado en el instante de firma ya no invalida la integridad criptográfica de la firma (Bouncy Castle acoplaba ambas comprobaciones al construir el verificador a partir del certificado completo en vez de su clave pública); un `digestAlgorithm` codificado como el OID del algoritmo de firma (no estándar, pero aceptado por Adobe) ya se verifica correctamente incluso sin atributos firmados — un segundo error, más profundo, encontrado desensamblando `SignerInformation.class` de Bouncy Castle: su propia corrección para este tipo de error (`translateBrokenRSAPkcs7`) solo cubre la variante histórica con SHA-1, no SHA-256 (§2.4). La cadena de certificados se extrae siempre que el CMS se pudo parsear, y todo resultado no `INTACT`/`UNSUPPORTED` lleva ahora un motivo legible y no sensible. Verificado con una ejecución manual real de la aplicación contra los dos PDFs originales (§7). Se añadió también la CA emisora cualificada de Camerfirma al almacén de confianza (un ancla **no autofirmada**, extraída directamente de la Lista de Confianza española), verificando que `PkixCertificateChainValidator` soporta anclas no autofirmadas (§2.7). |
| 2026-09-27 | (T09b) El `413` de subida ya lleva cuerpo `ProblemDetail` (antes vacío, porque el límite se comprueba antes de que Spring resuelva ningún controlador): nuevo `@RestControllerAdvice` sin acotar, exclusivo para esa excepción. `SectionError` y las notas de anomalía de enriquecimiento de firma ya no reflejan el mensaje bruto de una excepción inesperada. Un `IOException` leyendo el fichero subido se informa como `500`, no como `400` de fichero ausente. |
| 2026-09-28 | (T09d) Añadidas al almacén de confianza las CA emisoras cualificadas de FNMT ("AC FNMT Usuarios" y "AC Componentes Informáticos", esta última cubre también el servicio TSL "AC Representación" — mismo certificado), extraídas de la Lista de Confianza española igual que la de Camerfirma (§2.7, `truststore/SOURCES.md`): el PDF real firmado con FNMT pasó de `INCOMPLETE_CHAIN` a `TRUSTED` (confirmado con una ejecución manual real, resultados anonimizados abajo). Seguimiento de la revisión de T09c: el fallo estructural de `/ByteRange` ya siempre lleva una nota de anomalía no nula; el atajo de verificación para `digestAlgorithm` mal codificado ya tiene un test negativo (contenido manipulado → `INVALID_SIGNATURE`) y un test con atributos firmados presentes; el fallo al leer un fichero subido (`IOException`) ya se prueba también a través de la petición HTTP completa, no solo de forma aislada (§7). Verificación manual real (anonimizada): PDF firmado con FNMT → `INTACT`/`TRUSTED`; PDF firmado con Camerfirma → `INTACT`/`EXPIRED` (igual que en T09c, sin cambios para este caso). |
| 2026-09-28 | (T10) Comprobación de revocación OCSP/CRL real (`CompositeRevocationChecker`, `OcspClient`, `CrlClient`): OCSP primero con respaldo en CRL, verificación real de firma/frescura/*nonce*/identidad del respondedor, *timeout* de 2 s y límite de tamaño de respuesta configurables. Guarda SSRF con conexión anclada (`RevocationUrlGuard` + `PinnedHttpClient`, un cliente HTTP/1.1 propio sobre `Socket`): resuelve el nombre de host una sola vez y conecta exactamente a esa dirección, cerrando un hueco de *DNS rebinding* de una versión anterior que resolvía dos veces; rechaza direcciones privadas/reservadas (incluidas variantes IPv6) y cualquier URL que no sea `http`. Decisión de seguridad añadida durante la revisión: la revocación solo se comprueba para una cadena ya `TRUSTED`, y el certificado/emisor consultados vienen de `CertificateChainValidator#validatedPath` (los certificados que PKIX realmente usó), nunca de la cadena tal cual la presentó el CMS — cierra el vector de un certificado autofirmado con una URL OCSP interna, y el de un certificado adicional irrelevante embebido junto a una ruta genuina. Servidor HTTP de test propio sobre el JDK (`com.sun.net.httpserver.HttpServer`) en vez de WireMock, para evitar un posible conflicto de classpath con el Jetty de Spring Boot 4.1.1. Seguimiento de la revisión de T09d: motivo de reserva de `/ByteRange` sin mensaje probado directamente; variante con atributos firmados del atajo de `digestAlgorithm` con manipulación → `INVALID_SIGNATURE`; el 500 de lectura de subida se prueba también verificando que el caso de uso nunca se invoca. 211 → 256 tests. |
| 2026-09-28 | (T10b) Seguimiento de la revisión de T10: una cadena `TRUSTED` con `validatedPath` vacía ya informa un motivo explícito en vez del marcador `notChecked()` a secas; los envoltorios de seguridad de `CompositeRevocationChecker` registran por log el nombre de la clase de la excepción inesperada (nunca su mensaje) antes de informar `UNKNOWN`; `RawSocketTestServer` reutiliza un único `ExecutorService` por instancia y lo cierra en `close()` en vez de crear uno nuevo (sin cerrar) por llamada. (T11) Veredicto general por firma y de documento (`SignatureVerdict`/`OverallVerdict`, política pura `domain/policy/SignatureVerdictPolicy`, §2.10) combinando integridad, cadena y revocación, con la regla de varias firmas (una firma anterior modificada solo tras la firma no se penaliza si otra firma posterior cubre todo el fichero) y `modifiedAfterLastSignature` a nivel de documento. Expuesto en la API (`verdict`/`verdictReasons` por firma, `overallVerdict`/`modifiedAfterLastSignature` del documento). Nueva interfaz web estática "Validar" (`static/index.html`/`app.js`/`styles.css`, sin *frameworks* ni CDNs): arrastrar-y-soltar, comprobación de revocación opcional, banner de veredicto, tarjetas de firma con detalle expandible, sección de documento, descarga del informe JSON, tema claro/oscuro persistente, cabecera CSP acotada a la propia interfaz (`CspHeaderFilter`) sin afectar a Swagger UI. Verificación manual en un navegador real (modo claro y oscuro) encontró y corrigió un bug real: elementos `hidden` seguían visibles por una regla CSS posterior de igual especificidad; corregido con una única regla `[hidden] { display: none !important; }`. 268 → 298 tests. |
| 2026-09-28 | (T11) Corrección ortográfica del español visible de la interfaz web (`index.html`/`app.js`): tildes, `ñ` y pares que cambian de significado según el acento ("válida"/"valida", "Sí"/"si") restaurados en textos, `aria-label`, `title` y mensajes de error; sin cambios en identificadores de código, claves de objeto ni códigos de motivo (siguen en ASCII). `CspHeaderFilter` fuerza además `charset=UTF-8` en sus mismos cuatro *paths* exactos (`/`, `/index.html`, `/app.js`, `/styles.css`), en vez de la propiedad global `spring.servlet.encoding.force` (renombrada de `server.servlet.encoding.*` en Spring Boot 4), descartada por romper el `Content-Type: application/json` sin *charset* que espera `PdfAnalysisControllerTest`. 298 tests, sin cambios de recuento. |
| 2026-09-28 | (T11) Accesibilidad: el color de texto tenue (`--color-text-faint`) se subió a un contraste WCAG AA ≥ 4.5:1 sobre su fondo en ambos temas (claro y oscuro); de paso se corrigió un valor hexadecimal inválido de 7 dígitos (`#8890999`) que había quedado en el tema claro. 298 tests, sin cambios de recuento. |
| 2026-09-28 | **(T11c)** Seguimiento de la revisión de T11 (RDD, 3 bloques: A y B aprobados, C bajo presupuesto). SECURITY: `SignatureVerdictPolicy` exigía solo que *alguna* firma posterior fuera `INTACT` para eximir a una firma anterior modificada -- un atacante podía modificar un documento firmado por una entidad de confianza y volver a firmarlo con un certificado propio, y la firma original seguía apareciendo `VALID`; ahora exige que **todas** las firmas posteriores estén ellas mismas admitidas, o la firma anterior es `INVALID` con el nuevo motivo `MODIFIED_AFTER_SIGNING_BY_UNADMITTED_PARTY` (§2.10). `PdfAnalysisReport.overallVerdict()` distingue un fallo real de la sección de firmas (`ANALYSIS_INCOMPLETE`, nuevo valor de `OverallVerdict`) de un documento legítimamente sin firmar (`NO_SIGNATURES`). Interfaz "Validar" endurecida: un segundo `submit` mientras hay una petición en curso se ignora (`AbortController`), un payload `2xx` con forma inesperada muestra un error en vez de lanzar una excepción, y seleccionar un fichero inválido tras uno válido limpia la selección anterior. `CspHeaderFilter` compara la ruta relativa al *context path* en vez de `getRequestURI()` tal cual, que ya lo incluye (la cabecera dejaba de aplicarse bajo un *context path* no vacío). 298 → 307 tests. |
| 2026-09-28 | **(T11b)** Pantalla "Firmar": firma un PDF con AutoFirma (el certificado propio del usuario, la clave privada nunca sale de su equipo) usando la librería oficial **AutoScript 1.10.1**, vendida sin modificar como componente de terceros (`static/vendor/autofirma/`, §13) -- verificada su licencia dual GPL-2.0/EUPL-1.1 compatible con este proyecto GPL-3.0 antes de incluirla. `AutoScript.cargarAppAfirma()` se llama sin `setForceWSMode(true)` (ese flag fuerza el servidor intermedio, no el modo WebSocket, verificado leyendo el código fuente), así que la comunicación es directa con AutoFirma por `wss://127.0.0.1:<puerto>`, sin ningún servidor intermedio de guardado/recuperación. El botón "Validar este PDF" reutiliza literalmente `analyzeFile()`/`render.js` de la pantalla "Validar" en vez de duplicar esa lógica; `app.js` se dividió en módulos (`dom.js`, `render.js`, `validate.js`, `sign.js`). CSP ampliada con `connect-src wss://127.0.0.1:*`/`https://127.0.0.1:*` y `frame-src 'self' afirma:` (ambos verificados en el código de AutoScript, ninguno requirió `'unsafe-eval'`/`'unsafe-inline'` para scripts). Verificación manual (Chrome DevTools, AutoFirma no instalado en la máquina de desarrollo): selección de fichero con comprobación de bytes mágicos `%PDF-`, estado de espera, mensaje "AutoFirma no está instalado o no responde" tras agotar los reintentos, botón "Cancelar" -- todos correctos; no se intentó una firma real. 307 → 308 tests. |
| 2026-09-28 | **(T11e)** Ritmo de espaciado deliberado en toda la interfaz web (§2.14), reutilizando la escala `--space-*` existente, sin ningún *token* nuevo; excepción de diseño acotada a `index.html` documentada en `.impeccable/config.json` para el aviso `monotonous-spacing` (falso positivo confiado). Robustez de `sign.js`: contador de generación por intento verificado de nuevo en el navegador (una respuesta tardía de AutoFirma tras cancelar o tras un intento posterior se ignora), decodificación `base64` de una respuesta de éxito protegida con `try`/`catch` (mensaje en español en vez de una excepción sin capturar), "motivo de la firma" con tildes/ñ verificado contra el propio `_utf8_encode`/`Base64.encode` de `autoscript.js` vendido, y "Validar este PDF" ahora cambia a la pestaña "Validar" (`switchTab`, movida a `dom.js`, §10) y mueve el foco a `#results-heading` con *scroll*, respetando `prefers-reduced-motion`. **(T11d)** Javadoc de `SignatureVerdictPolicy.laterSignatureCoverage` corregido para describir el mecanismo real (verificación por veredicto ya calculado, no por `ByteRangeCoverage` directo); nuevos tests de regresión confirmando que la coincidencia de ruta de `CspHeaderFilter` ya era exacta (nunca por subcadena) y que el *charset* `UTF-8` ya se forzaba correctamente en las cuatro rutas estáticas, sin que ninguno de los dos avisos exigiera cambios de comportamiento. 308 → 320 tests. |
| 2026-09-28 | **(T11f)** Correcciones tras una firma real con AutoFirma (§2.5, §2.14): DN legible (Bouncy Castle `X500Name`/`BCStyle` en vez del RFC 2253 de la JDK, que volcaba `emailAddress` como `#16<hex>`; TDD con RED genuino), `commonName` propio en `CertificateInfo`/`CertificateInfoDto`; la cadena de certificados ya no se desborda de su tarjeta (`overflow-wrap`/`min-width: 0`) y muestra el CN en negrita con el DN completo como texto secundario; permisos PDF traducidos al español en la interfaz (`PERMISSION_TEXT`, códigos de la API sin cambios); footer sin ninguna referencia a "COAM", sustituido por un pie neutro con enlace al repositorio. Verificación manual real en el navegador: escritorio y 375&nbsp;px, claro y oscuro, sin errores de consola. 320 → 321 tests. |
| 2026-09-29 | **(T11g, T11h)** Incidencias PDF/A con descripción en español bajo el mensaje original en inglés (`PdfaIssueCatalog`, §2.9), tarjeta "Cifrado y permisos" con cifrado en una línea y etiqueta "Permisos del documento", CN de certificado sin escapes RFC 2253, ayudante de tests PKIX alineado con el formateador de producción y guarda frente a la validación tardía tras una nueva firma (§2.14). |
| 2026-09-29 | **(T12)** Contenedor: `Dockerfile` multi-etapa (capas de Spring Boot, JRE 25 Alpine, usuario no root, `HEALTHCHECK`), `docker-compose.yml` (512 MB, `read_only` + `tmpfs /tmp`, `no-new-privileges`, `cap_drop: ALL`) y perfil de JVM de bajo consumo (SerialGC, presupuesto explícito de memoria bajo 512 MB, cabeceras compactas, salida ante OOM; Tomcat acotado a 20 hilos); job de CI que construye la imagen sin publicarla y la prueba en ejecución (§4). |
| 2026-09-29 | **(T12e)** `max-concurrent` por defecto pasa de 2 a **1** (VM de 512 MB; 2 con ≥ 1 GB por variable de entorno) y la prueba de carga de CI deja de fallar por `memory.peak` (≥ 95 %, medido 502,3/512 MiB con 2) para vigilar solo señales reales de OOM (`oom_kill`, `OOMKilled`, reinicios, `OutOfMemoryError`). Decisión del usuario. 351 → 353 tests. |
| 2026-09-29 | **(T12f)** Límite de subida de 20 a **80 MB** (`application.yml`, cliente web y mensajes), contenedor de **2 GB** (`-Xmx1024m`, `tmpfs` de 160 MB, ampliado después a 256 MB tras comprobar que 2 subidas de 81 MB no cabían con margen), `max-concurrent=2` y `acquire-timeout=30s` por defecto tras medir en el VPS de OVHcloud (5 subidas de 83 MB: 5 × 200, pico 1013 MiB de 2048); el job de CI usa PDF de 79 MB con los nuevos límites. |
| 2026-09-29 | **(T12g)** Despliegue en un VPS de OVHcloud (Ubuntu 24.04, Docker, `ufw`, SSH solo con clave) con HTTPS (Caddy + Let's Encrypt), accesible en <https://vps-651608c6.vps.ovh.net/>; README adaptado (§1, §3, §4 «Despliegue en un VPS», §6, §8, §9). |
| 2026-09-29 | **(T12c)** *Bulkhead* de análisis simultáneos (`AnalysisBulkhead` + `AnalysisBulkheadFilter`, `pdfvalidator.analysis.max-concurrent=2`, `acquire-timeout=5s`): al saturarse, `503` `urn:pdfvalidator:error:busy` con `Retry-After`; la interfaz muestra el mensaje en español. Subidas siempre a `/tmp` (`file-size-threshold=0B`, ≤ 40 MB de los 64 MB del `tmpfs`), presupuesto de 492 MB sin cambios. Decisión del usuario: limitar la concurrencia en vez de usar ficheros temporales de PDFBox. Prueba de carga en el job `docker` de CI (5 subidas concurrentes de ~19 MB a un contenedor de 512 MB). 336 → 347 tests (§4). |
| 2026-09-29 | **(T12d)** Seguimiento de la revisión de T12c. El filtro del *bulkhead* ya no compara la URL exacta (se evadía con `;jsessionid=x` o `%61nalyze`): se aplica a toda petición `multipart/*` en cualquier ruta, con una tabla de variantes comprobada contra el servidor real; el `503` lleva `Connection: close` porque no se lee el cuerpo rechazado; la interfaz solo muestra "ocupado" para el tipo `urn:pdfvalidator:error:busy` (otro 503 → "no disponible"). CI: los resultados de cada `curl` en segundo plano se recogen explícitamente, la búsqueda de `OutOfMemoryError` ya no acierta con el *banner* de la JVM, y fallaba si `memory.peak` ≥ 95 % del límite (guarda retirada en T12e: hoy `memory.peak` es solo informativo). Primera medición real: `memory.peak` 502,3 de 512 MiB (margen ~10 MB con 2 análisis; opciones en §4). *Logger* de fuentes de PDFBox a `ERROR`. Sin Docker local, la comprobación de CI sigue siendo la del *runner* (§4). |
| 2026-09-29 | **(T12h)** HTTPS con Caddy y Let's Encrypt versionado en `deploy/` (`Caddyfile` con HSTS y `docker-compose.caddy.yml` en red del host); la aplicación publica el 8963 solo en `127.0.0.1`, de modo que el único acceso externo es <https://vps-651608c6.vps.ovh.net/>. |
| 2026-09-30 | README reorganizado para facilitar la comprensión: datos desactualizados corregidos (perfil de 2 GB / 80 MB, pestaña «Firmar», presentación entregada), sección 2 reordenada en orden de lectura y con introducción sencilla en cada apartado, e historial de desarrollo trasladado a §10 y §11. |
| 2026-09-30 | **(T16)** La indicación de las zonas de subida («Validar» y «Firmar») decía «hasta 20 MB» aunque el límite real es 80 MB; corregida y protegida con un test que la compara con `spring.servlet.multipart.max-file-size`. Diapositivas con capturas reales de ambas pantallas, hechas con PDF y certificados de demostración. |
| 2026-09-30 | **(T17)** Herramientas de calidad: umbral de cobertura JaCoCo (líneas 88 %, ramas 75 %) que hace fallar `verify`, SpotBugs + FindSecBugs y PMD/CPD en modo informe, PIT en el perfil `mutation` y flujo de CodeQL; los informes se suben como artefacto de CI. Sin cambios en el código de producción (§7). |
| 2026-09-30 | **(T18)** Endurecimiento de seguridad, bloque 1, a raíz de un pentest y una auditoría del código. (a) Una bomba de descompresión (PDF de 510 KB con un flujo `/FlateDecode` de 500 MB) agotaba el *heap* en *preflight* y, con `ExitOnOutOfMemoryError`, reiniciaba el contenedor: `DecodedSizeGuard` decodifica los flujos en *streaming* con límites (`max-decoded-stream-size` 32 MB, `max-decoded-total-size` 2 GB) y el PDF/A pasa a `NOT_VALIDATED` (`DOCUMENT_TOO_COMPLEX`) con el resto del informe intacto (§2.9). (b) Tomcat 11.0.26 y Jackson 3.1.7 / 2.21.6 por CVE conocidas (§10). (c) `checkRevocation=notabool` devuelve `400` (`invalid-parameter`) en vez de `500`. (d) `X-Content-Type-Options: nosniff` y `Referrer-Policy: no-referrer` en todas las respuestas (§2.14). |
| 2026-09-30 | **(T19)** Endurecimiento de seguridad, bloque 2: tiempo de validación de confianza. Un sello de tiempo solo es de confianza si su TSA declara `id-kp-timeStamping` y su cadena llega a un ancla en el `genTime` (y este no es futuro); la cadena del firmante se valida en ese `genTime` solo entonces, y si no a fecha de hoy. La fecha auto-declarada por el firmante ya no se usa nunca. Nuevo motivo `VALIDATED_AT_CURRENT_TIME`, campo `timestamp.trusted` en la API y textos de la interfaz («Sin sello de tiempo de confianza: se ha validado a fecha de hoy»; «Sello de tiempo (TSA no de confianza)»). Sustituye a la precedencia anterior (§10). |
| 2026-09-30 | **(T20)** Límites de recursos ante PDF hostiles: `RevisionCounter` deja de acumular millones de posiciones (arrays primitivos con tope `max-revision-markers`/`max-revisions`, `revisionCountLowerBound`); detalle por página limitado a `max-pages` con `pagesTruncated` y aviso en la interfaz; campos de firma limitados a `max-signature-fields`, con `ANALYSIS_INCOMPLETE` (nunca `VALID`) si quedan sin analizar, certificados por CMS (`max-certificates-per-signature`) y longitud de cadena (`max-chain-length`) acotados; límite de incidencias PDF/A aplicado durante la recogida (`max-pdfa-issues`, `TRUNCATED` exacto hasta 1 000 omitidas y «at least N» después). Campos DTO aditivos: `structure.pagesTruncated`, `structure.revisionCountLowerBound`. §2.3, 2.4, 2.5, 2.9, 2.10, 4, 10. |
| 2026-09-30 | **(T22)** Interfaz «Validar»: las páginas se agrupan por rotación y tamaño en desplegables cerrados por defecto con rangos de páginas («1–12, 15, 20–22») y una tarjeta nueva «Recortes» lista las páginas con `CropBox` distinto del `MediaBox` (§2.14). Sin cambios en el backend. |
| 2026-09-30 | **(T21)** Endurecimiento de la revocación (§2.8) a raíz de una auditoría del código. (a) Se comprueba **cada certificado de la ruta validada salvo el ancla**, no solo el firmante: una CA intermedia revocada con el firmante `GOOD` daba `VALID`; ahora cualquier `REVOKED` revoca la ruta, cualquier `UNKNOWN` la deja en `UNKNOWN` (*fail-closed*) y el detalle nombra la CA responsable. (b) **Un único plazo por firma** (`total-timeout`, 6 s) compartido por OCSP y CRL de todos los certificados, más deduplicación y tope de 3 URLs por método: antes cada URL tenía su propio *timeout* y un certificado con muchas URLs alargaba la espera y el tráfico saliente. (c) La **resolución DNS** corre bajo el plazo, en un grupo acotado de 16 hilos (antes un DNS lento bloqueaba más allá del *timeout*), conservando la resolución única y la conexión anclada. (d) Tope de longitud de línea (8 KB), número (100) y tamaño total (64 KB) de cabeceras y *trailers* `chunked`. (e) La guarda SSRF no normalizaba IPv4-compatible, NAT64 ni 6to4: `::127.0.0.1`, `64:ff9b::7f00:1` y `2002:7f00:1::` no se rechazaban (confirmado con un test en rojo) y ahora sí. Todos los límites son propiedades `pdfvalidator.revocation.*` (§4). `./mvnw -B verify` en verde, 472 tests, JaCoCo 91.05 % líneas / 79.01 % ramas. |
| 2026-09-30 | **(T23)** Restos de la auditoría. (a) Ningún texto de excepción de una biblioteca llega ya al informe JSON: las notas del sello de tiempo (*"Malformed RFC 3161 timestamp token"*, *"TSA signature verification failed"*, *"TSA certificate data could not be mapped"*) y las incidencias PDF/A (*"The document declares a PDF header but could not be parsed"*, *"... could not be probed for encryption"*, *"PDF/A-1b validation failed"*, *"PDF/A-1b validation could not parse the document"*) son textos fijos; el detalle se registra por log en una sola línea sin caracteres de control y de 300 caracteres como máximo. Los rechazos de URL de revocación y `CompositeRevocationChecker` se dejan como estaban, con la justificación de §10, y un test fija que no repiten el host. (b) Imágenes base del `Dockerfile` y de Caddy fijadas por *digest* (§4); la compilación Docker solo se verifica en CI. (c) Swagger UI y `/v3/api-docs` públicos como riesgo aceptado, con el modo de desactivarlos (§10). 472 → 477 tests. |
| 2026-10-01 | **(T24)** Análisis estático: triaje y puerta (§7). SpotBugs pasa de 26 avisos a 0 y PMD de 52 a 24 (solo prioridad 3 de complejidad); CPD de 2 duplicados a 0. Se corrigieron los defectos reales (copias defensivas en los DTO, subida sin nombre de fichero, que antes daba 500, un `SecureRandom` compartido para los nonce OCSP, causa conservada al relanzar, colecciones vacías en lugar de `null`, `PdfBoxDocumentReader` `final`) y se compartieron el bucle de URL de OCSP/CRL y el lector de la declaración PDF/A. Dos exclusiones de SpotBugs justificadas en `config/spotbugs/exclude.xml`. Las tres herramientas son ahora una puerta de `verify` (SpotBugs en *Medium*, PMD en prioridad 1-2, CPD en 100 tokens), con comprobación negativa de cada una. 485 tests. |
| 2026-10-01 | **(T25)** Diapositivas actualizadas a 17: capturas nuevas de «Validar» (sello de tiempo de confianza, fecha declarada no verificada), diapositiva de páginas agrupadas y recortes, calidad con 486 tests y las puertas de análisis estático, y diapositiva de seguridad (auditoría, pentest y correcciones). PDF y PPTX en `docs/` (§9). |
| 2026-10-01 | **(T26)** (a) El certificado de la TSA ya no tiene que ir dentro del sello: un sello pedido con `certReq=false` (RFC 3161 §2.4.1) se resuelve buscando el certificado en el CMS de la firma y, después, entre los anclas de confianza (nuevo puerto de dominio `TrustedCertificateSource`, que implementa `TrustAnchorProvider`), con la condición de coincidir con el identificador del firmante del sello **y** con el hash `ESSCertID`/`ESSCertIDv2` firmado por la TSA, de modo que no se puede sustituir por otro certificado; la decisión de confianza sigue en `AnalyzePdfUseCase` (§2.6). (b) Seguimientos de T12f: `server.tomcat.connection-timeout=20s` libera el hueco de análisis de un cliente que deja de enviar el cuerpo, y `deploy/Caddyfile` añade `read_body 10m` como plazo máximo de toda la subida (validado con `caddy validate` en la imagen fijada 2.11.4; `read_body_idle` no existe en esa versión); prueba de que las peticiones no multiparte no compiten por el permiso; Javadoc de `AnalysisProperties` con los valores reales; filas del historial sobre la guarda del 95 % y el `tmpfs` corregidas (§4, §7). 486 → 494 tests. |
| 2026-10-02 | **(T14)** El almacén de confianza se genera desde las Listas de Confianza oficiales: la herramienta de mantenimiento `TslSync` (`./mvnw -q -Ptsl-sync`, fuera del jar) descarga la LOTL de la UE y la TSL española, verifica sus firmas XML contra firmantes fijados (los seis del Diario Oficial para la LOTL; los que anuncia la LOTL para la TSL) con XML seguro, HTTPS, tope de tamaño y comprobación de `NextUpdate`, y regenera `src/main/resources/truststore/` (`.crt`, `index.txt`, `SOURCES.md`) de forma determinista. `TrustAnchorProvider` lee `index.txt`. Las 9 anclas curadas a mano se sustituyen por 145 (77 `CA/QC` de firma electrónica y 68 `TSA/QTST`; LOTL n.º 395, TSL n.º 189); quedan fuera AC CAMERFIRMA FOR LEGAL PERSONS - 2016 y AC Componentes Informáticos (solo sellos/web). Tarea semanal `.github/workflows/tsl-sync.yml` que abre un PR si cambia. Pendiente a mano: cotejar los pines con OJ C/2026/1944 y activar «Allow GitHub Actions to create and approve pull requests» (§2.7, §4, §10). 494 → 528 tests. |
| 2026-10-02 | Documentados en §4 las huellas fijadas de la LOTL (para cotejarlas con el Diario Oficial) y el alcance limitado a la Lista de Confianza española: las firmas de CA de otros países de la UE salen `NOT_ADMITTED`. |
| 2026-10-02 | Diapositivas actualizadas (17): 528 tests, almacén de confianza generado desde la Lista de Confianza oficial con actualización semanal, y alcance limitado a CA españolas. PDF y PPTX en `docs/` (§9). |

## 12. Repositorio y licencia

- Código fuente: <https://github.com/avalinani/verificador>
- Licencia: [GNU GPL v3.0](LICENSE). Es compatible con las dependencias principales: Apache PDFBox (Apache-2.0) y Bouncy Castle (licencia MIT).

## 13. Componentes de terceros

> **Nota:** esta sección explica una decisión de ingeniería tomada para este TFM (cómo se incluyó un componente de terceros y por qué), **no es un dictamen legal**. Ante cualquier duda real sobre compatibilidad de licencias, consúltese a un profesional cualificado.

La pantalla "Firmar" (§2.15) usa **AutoScript**, la librería JavaScript oficial de integración con AutoFirma, publicada por el proyecto Cliente @firma de la Administración General del Estado.

- **Origen**: <https://github.com/ctt-gob-es/clienteafirma>, ruta `afirma-ui-miniapplet-deploy/src/main/webapp/js/autoscript.js`, rama `master`.
- **Versión**: 1.10.1 (`AutoScript.VERSION`, comprobado en el propio fichero descargado).
- **Integridad verificada**: SHA-1 de blob Git `dc9401987c4cd6834cefbb68ec1adee038557f5b` y tamaño 255151 bytes, ambos comprobados con `git hash-object`/`wc -c` contra el fichero descargado y coincidentes con los valores esperados antes de incluirlo.
- **Licencia**: doble licencia **GPL-2.0** / **EUPL-1.1**, a elección de quien la use (indicado en el propio `LICENSE.txt` del proyecto oficial). Ambos textos completos se incluyen sin modificar (`gpl-2.0.txt`, `EUPL-v1.1.pdf`), igual que el propio `LICENSE.txt`.

**Cómo convive con la licencia GPL-3.0 de este proyecto (decisión razonada, no un dictamen legal)**: `autoscript.js` se incluye **sin modificar**, como un fichero de terceros independiente (`static/vendor/autofirma/`), cargado en el navegador como un `<script>` aparte y usado únicamente a través de su API pública documentada (`AutoScript.cargarAppAfirma`, `AutoScript.sign`, `SupportDialog.enableSupportDialog`) -- nunca parcheado, minificado, ni mezclado línea a línea con el código propio de este proyecto. Se trata como una **agregación** de dos componentes con licencia distinta que se distribuyen juntos (el mismo patrón que un sitio web GPL que sirve una librería JavaScript de terceros sin modificar bajo su propia licencia), no como una obra derivada única: GPL-2.0 y GPL-3.0 no son binariamente compatibles palabra por palabra sin la cláusula "or later" de por medio, pero EUPL-1.1 sí está reconocida por la Comisión Europea como compatible con GPL-2.0 (y v2-or-later) precisamente para casos así, y AutoScript se distribuye bajo esa doble licencia a propósito para permitir esta convivencia. `NOTICE.md` (`static/vendor/autofirma/NOTICE.md`) documenta el componente, su versión, origen, huella de integridad y esta misma decisión, junto al propio fichero.

Ningún otro componente de terceros de este proyecto se distribuye como fichero embebido: el resto de dependencias (Spring Boot, Apache PDFBox, Bouncy Castle, springdoc, ArchUnit) llegan por Maven y se declaran en `pom.xml` con sus licencias respectivas (§12).
