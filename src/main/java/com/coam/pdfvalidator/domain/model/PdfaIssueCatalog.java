package com.coam.pdfvalidator.domain.model;

import java.util.Map;
import java.util.Optional;

/**
 * Translates a PDFBox {@code preflight} validation error code (as reported
 * on {@link PdfaIssue#code()}) into neutral, professional Spanish for the
 * web UI, alongside the original English message PDFBox itself produced --
 * see {@code api.dto.PdfAnalysisReportMapper}, which uses this to fill
 * {@code PdfaIssueDto.messageEs()}.
 *
 * <p>Every code and its exact hierarchy come from {@code
 * org.apache.pdfbox.preflight.PreflightConstants} (the {@code ERROR_*}
 * constants of the vendored {@code preflight-3.0.8} dependency), inspected
 * with {@code javap -constants} rather than guessed. PDFBox's own codes are
 * already dotted category paths (e.g. {@code "3.1.3"} is a child of {@code
 * "3.1"}, itself a child of {@code "3"}), so this catalog stores one
 * translation per constant -- at every level, main category down to leaf --
 * and {@link #spanishMessage(String)} looks up the exact code first, then
 * walks up to its parent category one segment at a time. A code (or, after
 * exhausting the walk, an entire top-level category) this catalog does not
 * recognize -- e.g. PDFBox's own {@code ERROR_UNKNOWN_ERROR} ({@code "-1"}),
 * which names an explicitly uncategorized error rather than a real PDF/A
 * rule, or this project's own non-PDFBox synthetic codes ({@code
 * "NOT_VALIDATED"}, {@code "TRUNCATED"}, see {@code PreflightPdfaValidator})
 * -- yields no translation at all: the UI then shows only the original
 * English message for that issue, never a wrong or fabricated one.
 *
 * <p>The category structure (verified from the constants, not assumed):
 * {@code 1.x} document syntax, {@code 2.x} graphics/color space, {@code 3.x}
 * fonts, {@code 4.x} extended graphics state transparency, {@code 5.x}
 * annotations, {@code 6.x} actions, {@code 7.x} XMP metadata, {@code 8.x}
 * document processing.
 */
public final class PdfaIssueCatalog {

    private PdfaIssueCatalog() {
    }

    private static final Map<String, String> TRANSLATIONS = Map.ofEntries(
            // 1.x -- ERROR_SYNTAX_*: document syntax
            Map.entry("1", "Error de sintaxis del documento PDF."),
            Map.entry("1.0", "Error de sintaxis en un objeto del documento."),
            Map.entry("1.0.1", "Un diccionario supera el número máximo de entradas permitido."),
            Map.entry("1.0.2", "Un array supera el número máximo de elementos permitido."),
            Map.entry("1.0.3", "Un nombre supera la longitud máxima permitida."),
            Map.entry("1.0.4", "Una cadena de texto literal supera la longitud máxima permitida."),
            Map.entry("1.0.5", "Una cadena hexadecimal supera la longitud máxima permitida."),
            Map.entry("1.0.6", "Un valor numérico está fuera del rango permitido."),
            Map.entry("1.0.7", "Una clave de diccionario no es válida."),
            Map.entry("1.0.8", "El código de idioma no cumple el formato RFC 1766."),
            Map.entry("1.0.9", "El número de un objeto indirecto está fuera del rango permitido."),
            Map.entry("1.0.10", "Un identificador de carácter (CID) está fuera del rango permitido."),
            Map.entry("1.0.11", "Una cadena hexadecimal no tiene un número par de dígitos."),
            Map.entry("1.0.12", "Una cadena hexadecimal contiene caracteres no válidos."),
            Map.entry("1.0.13", "Falta el desplazamiento (offset) de un objeto en la tabla de referencias cruzadas."),
            Map.entry("1.0.14",
                    "El desplazamiento (offset) de un objeto en la tabla de referencias cruzadas no es válido."),
            Map.entry("1.1", "La cabecera del fichero PDF no es válida."),
            Map.entry("1.1.1", "El primer carácter de la cabecera del fichero no es el esperado (\"%\")."),
            Map.entry("1.1.2", "La cabecera del fichero no declara un tipo de fichero PDF válido."),
            Map.entry("1.2", "El cuerpo del documento contiene un error de sintaxis."),
            Map.entry("1.2.1", "Los delimitadores de un objeto (\"obj\"/\"endobj\") no son válidos."),
            Map.entry("1.2.2", "Los delimitadores de un flujo (\"stream\"/\"endstream\") no son válidos."),
            Map.entry("1.2.3", "Un diccionario no es válido."),
            Map.entry("1.2.4", "Falta la entrada /Length de un flujo (stream)."),
            Map.entry("1.2.5", "La entrada /Length de un flujo (stream) no es válida."),
            Map.entry("1.2.6", "Un flujo (stream) de tipo F/FFilter/FDecodeParms no está permitido."),
            Map.entry("1.2.7", "Un filtro aplicado a un flujo (stream) no está permitido en PDF/A."),
            Map.entry("1.2.8", "El flujo de contenido de una página no es válido."),
            Map.entry("1.2.9", "El documento contiene ficheros incrustados, no permitidos en PDF/A-1b."),
            Map.entry("1.2.10", "El flujo de contenido usa un operador no soportado."),
            Map.entry("1.2.11", "Un operador del flujo de contenido recibe un argumento no válido."),
            Map.entry("1.2.12", "Un flujo (stream) referencia un filtro no definido."),
            Map.entry("1.2.13", "Un flujo (stream) está dañado y no se puede decodificar."),
            Map.entry("1.2.14", "El documento no tiene un diccionario /Catalog válido."),
            Map.entry("1.3", "La tabla de referencias cruzadas (xref) no es válida."),
            Map.entry("1.4", "El trailer del documento no es válido."),
            Map.entry("1.4.1", "Falta la entrada /ID en el trailer del documento."),
            Map.entry("1.4.2", "El documento está cifrado (/Encrypt), no permitido en PDF/A."),
            Map.entry("1.4.3", "El trailer no es del tipo esperado."),
            Map.entry("1.4.4", "Falta la entrada /Size en el trailer del documento."),
            Map.entry("1.4.5", "Falta la entrada /Root en el trailer del documento."),
            Map.entry("1.4.6", "El identificador (/ID) no es consistente entre las revisiones del documento."),
            Map.entry("1.4.7",
                    "El catálogo del documento referencia ficheros incrustados, no permitidos en PDF/A-1b."),
            Map.entry("1.4.8",
                    "El catálogo del documento usa contenido opcional (capas), no permitido en PDF/A-1b."),
            Map.entry("1.4.9", "El esquema de marcadores (/Outlines) del documento no es válido."),
            Map.entry("1.4.10", "Falta o no es válido el marcador de fin de fichero (%%EOF)."),

            // 2.x -- ERROR_GRAPHIC_*: graphics and color space
            Map.entry("2", "Error en el contenido gráfico del documento."),
            Map.entry("2.1", "Un elemento gráfico no es válido."),
            Map.entry("2.1.1", "Una caja delimitadora (BBox) no es válida."),
            Map.entry("2.1.2", "Una entrada del diccionario /OutputIntent no es válida."),
            Map.entry("2.1.3", "El valor /S del diccionario /OutputIntent no es válido."),
            Map.entry("2.1.4", "El perfil ICC del /OutputIntent no es válido."),
            Map.entry("2.1.5",
                    "El documento declara más de un perfil ICC de salida distinto, no permitido en PDF/A-1b."),
            Map.entry("2.1.6", "La versión del perfil ICC del /OutputIntent es más reciente de lo permitido."),
            Map.entry("2.1.7", "Falta un campo obligatorio en un objeto gráfico."),
            Map.entry("2.1.8", "Se supera el número máximo de estados gráficos anidados."),
            Map.entry("2.1.9", "Falta un objeto gráfico referenciado."),
            Map.entry("2.1.10", "El tipo de un objeto externo (XObject) no es válido."),
            Map.entry("2.2", "Uso de transparencia no permitido en el contenido gráfico."),
            Map.entry("2.2.1", "Un grupo de transparencia no es válido."),
            Map.entry("2.2.2", "Se usa una máscara de transparencia (SMask), no permitida en PDF/A-1b."),
            Map.entry("2.3", "Un diccionario gráfico contiene una clave no esperada."),
            Map.entry("2.3.2", "Una clave de un diccionario gráfico tiene un valor no esperado."),
            Map.entry("2.4", "El espacio de color no es válido."),
            Map.entry("2.4.1", "El espacio de color RGB no es válido o falta el perfil ICC de salida."),
            Map.entry("2.4.2", "El espacio de color CMYK no es válido o falta el perfil ICC de salida."),
            Map.entry("2.4.3",
                    "Se usa un espacio de color dependiente del dispositivo sin haber declarado un perfil de color (/OutputIntent)."),
            Map.entry("2.4.4", "El espacio de color es desconocido o no está soportado."),
            Map.entry("2.4.5", "El espacio de color /Pattern no está permitido en este contexto."),
            Map.entry("2.4.6", "La definición de un patrón (pattern) no es válida."),
            Map.entry("2.4.7", "El espacio de color alternativo no es válido."),
            Map.entry("2.4.8", "El espacio de color indexado no es válido."),
            Map.entry("2.4.9", "El espacio de color no está permitido en PDF/A-1b."),
            Map.entry("2.4.10", "El espacio de color DeviceN supera el número máximo de componentes permitido."),
            Map.entry("2.4.11", "El espacio de color basado en ICC (ICCBased) no es válido."),
            Map.entry("2.4.12", "Falta el flujo del perfil ICC de un espacio de color ICCBased."),

            // 3.x -- ERROR_FONTS_*: fonts
            Map.entry("3", "Error en una fuente del documento."),
            Map.entry("3.1", "Los datos de una fuente no son válidos."),
            Map.entry("3.1.1", "El diccionario de la fuente no es válido: faltan campos obligatorios."),
            Map.entry("3.1.2", "El descriptor de la fuente (FontDescriptor) no es válido."),
            Map.entry("3.1.3", "Falta el fichero embebido de la fuente (FontFile) o no es válido."),
            Map.entry("3.1.4", "Falta la entrada /CharSet en una fuente de tipo subconjunto (subset)."),
            Map.entry("3.1.5", "La codificación (encoding) de la fuente no es válida."),
            Map.entry("3.1.6", "Las métricas (anchos de carácter) de la fuente no son consistentes."),
            Map.entry("3.1.7", "Los datos de una fuente CID (CIDKeyed) no son válidos."),
            Map.entry("3.1.8", "La información del sistema de codificación (CIDSystemInfo) de la fuente no es válida."),
            Map.entry("3.1.9", "El mapa CIDToGIDMap de la fuente no es válido."),
            Map.entry("3.1.10", "El CMap de la fuente CID no es válido o no está presente."),
            Map.entry("3.1.11", "Falta la entrada /CIDSet en una fuente CID de tipo subconjunto (subset)."),
            Map.entry("3.1.12", "Error al interpretar la codificación de la fuente."),
            Map.entry("3.1.13", "Error de lectura al procesar la codificación de la fuente."),
            Map.entry("3.1.14", "El tipo de fuente es desconocido o no está soportado."),
            Map.entry("3.2", "El fichero embebido de la fuente está dañado."),
            Map.entry("3.2.1", "El fichero de la fuente Type1 embebida está dañado."),
            Map.entry("3.2.2", "El fichero de la fuente TrueType embebida está dañado."),
            Map.entry("3.2.3", "El fichero de la fuente CID embebida está dañado."),
            Map.entry("3.2.4", "La definición de la fuente Type3 está dañada."),
            Map.entry("3.2.5", "El CMap embebido de la fuente CID está dañado."),
            Map.entry("3.3", "Falta un glifo usado por el texto del documento."),
            Map.entry("3.3.1", "Un carácter usado en el texto no tiene glifo en la fuente embebida."),
            Map.entry("3.3.2", "Se referencia una fuente que no está definida en los recursos de la página."),

            // 4.x -- ERROR_TRANSPARENCY_*: extended graphics state transparency
            Map.entry("4", "Error de transparencia en el estado gráfico extendido."),
            Map.entry("4.1", "El estado gráfico extendido (ExtGState) no es válido."),
            Map.entry("4.1.1",
                    "El estado gráfico extendido declara una máscara de transparencia (SMask), no permitida en PDF/A-1b."),
            Map.entry("4.1.2",
                    "El estado gráfico extendido declara un valor de opacidad distinto de 1.0, no permitido en PDF/A-1b."),
            Map.entry("4.1.3",
                    "El estado gráfico extendido declara un modo de fusión (blend mode) distinto de \"Normal\", no permitido en PDF/A-1b."),

            // 5.x -- ERROR_ANNOT_*: annotations
            Map.entry("5", "Error en una anotación del documento."),
            Map.entry("5.1", "Faltan campos obligatorios en una anotación."),
            Map.entry("5.1.1", "Falta el subtipo (/Subtype) de la anotación."),
            Map.entry("5.1.2", "Falta la apariencia normal (/AP /N) de la anotación."),
            Map.entry("5.1.3", "Falta el diccionario de la anotación."),
            Map.entry("5.2", "La anotación contiene un elemento no permitido en PDF/A-1b."),
            Map.entry("5.2.1", "El subtipo de la anotación no está permitido en PDF/A-1b."),
            Map.entry("5.2.2", "Un indicador (flag) de la anotación no está permitido en PDF/A-1b."),
            Map.entry("5.2.3", "El color declarado en la anotación no está permitido en este contexto."),
            Map.entry("5.2.4", "El destino (/Dest) de la anotación no está permitido."),
            Map.entry("5.2.5", "La anotación declara acciones adicionales (/AA), no permitidas en PDF/A-1b."),
            Map.entry("5.2.6", "Un indicador (flag) de la anotación no está recomendado en PDF/A-1b."),
            Map.entry("5.2.7",
                    "El catálogo del documento declara acciones adicionales (/AA), no permitidas en PDF/A-1b."),
            Map.entry("5.3", "Un elemento de la anotación no es válido."),
            Map.entry("5.3.1", "El contenido de la apariencia (/AP) de la anotación no es válido."),
            Map.entry("5.3.2", "El valor de opacidad (/CA) de la anotación no es válido."),
            Map.entry("5.3.3", "El destino (/Dest) de la anotación no es válido."),

            // 6.x -- ERROR_ACTION_*: actions
            Map.entry("6", "Error en una acción del documento."),
            Map.entry("6.1", "Una acción del documento no es válida."),
            Map.entry("6.1.1", "Falta una clave obligatoria en el diccionario de la acción."),
            Map.entry("6.1.3", "El tipo de la acción no es válido."),
            Map.entry("6.1.4", "El campo /H de una acción \"Hide\" no es válido."),
            Map.entry("6.1.5", "Falta el diccionario de la acción."),
            Map.entry("6.2", "Se usa un tipo de acción no permitido en PDF/A-1b."),
            Map.entry("6.2.1", "Se usa una acción con nombre (/Named) no permitida en PDF/A-1b."),
            Map.entry("6.2.2", "Se usa una acción adicional (/AA) no permitida en PDF/A-1b."),
            Map.entry("6.2.3",
                    "Un campo de formulario declara una acción adicional (/AA), no permitida en PDF/A-1b."),
            Map.entry("6.2.4", "Una anotación de tipo widget declara una acción no permitida en PDF/A-1b."),
            Map.entry("6.2.5",
                    "Se usa un tipo de acción explícitamente prohibido en PDF/A-1b (por ejemplo, /Launch, /Sound, /Movie o /JavaScript)."),
            Map.entry("6.2.6",
                    "Se usa un tipo de acción no definido en la especificación PDF, no permitido en PDF/A-1b."),

            // 7.x -- ERROR_METADATA_*: XMP metadata
            Map.entry("7", "Error en los metadatos XMP del documento."),
            Map.entry("7.0", "Falta el atributo rdf:about en una descripción de los metadatos XMP."),
            Map.entry("7.0.0", "Los metadatos usan una sintaxis de paquete XMP (xpacket) obsoleta."),
            Map.entry("7.0.1",
                    "El atributo rdf:about no tiene el mismo valor en todas las descripciones de los metadatos XMP."),
            Map.entry("7.1", "Los metadatos XMP no tienen un formato válido."),
            Map.entry("7.1.1", "Los metadatos XMP contienen una propiedad desconocida en un esquema conocido."),
            Map.entry("7.1.2", "El formato de una propiedad de los metadatos XMP no es válido."),
            Map.entry("7.1.3", "El esquema de los metadatos XMP es desconocido."),
            Map.entry("7.1.4", "El flujo (stream) de metadatos no es válido."),
            Map.entry("7.1.5", "El paquete XMP (xpacket) no es válido."),
            Map.entry("7.2", "Los metadatos XMP no coinciden con los valores equivalentes del diccionario del documento."),
            Map.entry("7.3", "Falta un esquema de descripción obligatorio en los metadatos XMP."),
            Map.entry("7.4", "Falta el URI de un espacio de nombres en los metadatos XMP."),
            Map.entry("7.4.1", "El URI de un espacio de nombres de los metadatos XMP no es correcto."),
            Map.entry("7.4.2", "El prefijo de un espacio de nombres de los metadatos XMP no es correcto."),
            Map.entry("7.5", "Falta una propiedad obligatoria en los metadatos XMP."),
            Map.entry("7.5.1", "El valor de la propiedad \"categoría\" de los metadatos XMP no es válido."),
            Map.entry("7.6", "Los metadatos XMP declaran un tipo de valor desconocido."),
            Map.entry("7.11", "Falta el esquema de identificación PDF/A (pdfaid) en los metadatos XMP."),
            Map.entry("7.11.1", "El nivel de conformidad PDF/A declarado en los metadatos XMP no es válido."),
            Map.entry("7.11.2", "La versión de PDF/A declarada en los metadatos XMP no es válida."),
            Map.entry("7.12",
                    "El diccionario de información del documento (/Info) está dañado o no es coherente con los metadatos XMP."),

            // 8.x -- ERROR_PDF_PROCESSING*: document processing
            Map.entry("8", "Error al procesar el documento."),
            Map.entry("8.1", "Falta un elemento necesario para completar el procesamiento del documento."));

    /**
     * The Spanish translation for {@code code}, or {@link Optional#empty()}
     * if neither {@code code} nor any of its parent categories (walking up
     * one dot-separated segment at a time) is in this catalog -- see the
     * class Javadoc for exactly which codes that applies to.
     */
    public static Optional<String> spanishMessage(String code) {
        String candidate = code;
        while (candidate != null && !candidate.isEmpty()) {
            String translation = TRANSLATIONS.get(candidate);
            if (translation != null) {
                return Optional.of(translation);
            }
            candidate = parentCategory(candidate);
        }
        return Optional.empty();
    }

    /** {@code "3.1.3"} -&gt; {@code "3.1"} -&gt; {@code "3"} -&gt; {@code null}. */
    private static String parentCategory(String code) {
        int lastDot = code.lastIndexOf('.');
        return lastDot == -1 ? null : code.substring(0, lastDot);
    }
}
