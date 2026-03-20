package cz.muni.xmichalk.traverser;

import cz.muni.xmichalk.integrity.IIntegrityVerifier;
import cz.muni.xmichalk.integrity.StorageDocumentIntegrityVerifier;
import cz.muni.xmichalk.models.ItemToTraverse;
import cz.muni.xmichalk.provServiceAPI.IProvServiceAPI;
import cz.muni.xmichalk.provServiceAPI.ProvServiceAPI;
import cz.muni.xmichalk.provServiceTable.IProvServiceTable;
import cz.muni.xmichalk.provServiceTable.ProvServiceTable;
import cz.muni.xmichalk.traversalPriority.ETraversalPriority;
import cz.muni.xmichalk.traversalPriority.IntegrityThenOrderedValidity;
import cz.muni.xmichalk.validity.DemoValidityVerifier;
import cz.muni.xmichalk.validity.EValidityCheck;
import cz.muni.xmichalk.validity.IValidityVerifier;
import io.swagger.v3.oas.annotations.ExternalDocumentation;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.File;
import java.io.IOException;
import java.util.Comparator;
import java.util.Map;

@Configuration
@SecurityScheme(name = "auth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT")
@OpenAPIDefinition(
        info = @Info(
                title = "Provenance traversal API", version = "1.0.0",
                description = "REST API for traversing through the provenance chain."
        ), externalDocs = @ExternalDocumentation(
        description = "Query structure documentation",
        url = "https://github.com/JuliaMeee/mthesis-distributed-provenance-search#query-structure"
)
)
public class TraverserConfig {
    @Value("${traverser.concurrencyDegree:10}")
    private int traverserConcurrencyDegree;

    @Value("${traverser.preferProvServiceFromConnectors:false}")
    private boolean preferProvServiceFromConnectors;

    @Value("${traverser.omitEmptyResults:false}")
    private boolean omitEmptyResults;

    @Value("${demoValidityVerifier.authHeader}")
    private String authHeader;

    @Bean public IProvServiceTable provServiceTable() {
        ProvServiceTable table = new ProvServiceTable();
        try {
            ClassPathResource resource = new ClassPathResource("provServiceTable.json");
            table.loadFromJson(resource.getInputStream());
        } catch (IOException e) {
            throw new RuntimeException("Failed to load traverser table", e);
        }
        return table;
    }

    @Bean public IProvServiceAPI provServiceAPI() {
        return new ProvServiceAPI();
    }

    @Bean public IIntegrityVerifier integrityVerifier() {
        return new StorageDocumentIntegrityVerifier();
    }

    @Bean public Map<EValidityCheck, IValidityVerifier> validityVerifiers(IProvServiceAPI provServiceAPI)
            throws IOException {
        ClassPathResource simpleSemanticResource =
                new ClassPathResource("validitySpecifications" + File.separator + "simpleSemanticConstraints.json");
        ClassPathResource isSamplingBundleResource =
                new ClassPathResource("validitySpecifications" + File.separator + "isSamplingBundle.json");
        ClassPathResource isProcessingBundleResource =
                new ClassPathResource("validitySpecifications" + File.separator + "isProcessingBundle.json");

        return Map.of(
                EValidityCheck.DEMO_SIMPLE_CONSTRAINTS,
                new DemoValidityVerifier(provServiceAPI, simpleSemanticResource.getInputStream(), authHeader),
                EValidityCheck.DEMO_IS_SAMPLING_BUNDLE,
                new DemoValidityVerifier(provServiceAPI, isSamplingBundleResource.getInputStream(), authHeader),
                EValidityCheck.DEMO_IS_PROCESSING_BUNDLE,
                new DemoValidityVerifier(provServiceAPI, isProcessingBundleResource.getInputStream(), authHeader)
        );
    }

    @Bean public Map<ETraversalPriority, Comparator<ItemToTraverse>> traversalPriorityComparators() {
        return Map.of(ETraversalPriority.INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS, new IntegrityThenOrderedValidity());
    }

    @Bean public Traverser traverser(
            IProvServiceTable provServiceTable,
            IProvServiceAPI provServiceAPI,
            IIntegrityVerifier integrityVerifier,
            Map<EValidityCheck, IValidityVerifier> validityVerifiers,
            Map<ETraversalPriority, Comparator<ItemToTraverse>> traversalPriorityComparators
    ) {
        return new Traverser(
                provServiceTable,
                provServiceAPI,
                integrityVerifier,
                traverserConcurrencyDegree,
                preferProvServiceFromConnectors,
                omitEmptyResults,
                validityVerifiers,
                traversalPriorityComparators
        );
    }
}
