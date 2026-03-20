package cz.muni.xmichalk.queryService;

import com.fasterxml.jackson.databind.ObjectMapper;
import cz.muni.fi.cpm.merged.CpmMergedFactory;
import cz.muni.fi.cpm.model.ICpmFactory;
import cz.muni.fi.cpm.model.ICpmProvFactory;
import cz.muni.fi.cpm.vanilla.CpmProvFactory;
import cz.muni.xmichalk.storage.IStorage;
import cz.muni.xmichalk.storage.Storage;
import cz.muni.xmichalk.storage.mockedAuth.MockedAuthConfig;
import cz.muni.xmichalk.storage.mockedAuth.MockedAuthStorage;
import io.swagger.v3.oas.annotations.ExternalDocumentation;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.openprovenance.prov.vanilla.ProvFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.File;
import java.io.IOException;

@Configuration
@SecurityScheme(name = "auth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT")
@OpenAPIDefinition(
        info = @Info(
                title = "Bundle query API", version = "1.0.0",
                description = "REST API for answering queries about bundles."
        ), externalDocs = @ExternalDocumentation(
        description = "Query structure documentation",
        url = "https://github.com/JuliaMeee/mthesis-distributed-provenance-search#query-structure"
)
)
public class Config {

    @Bean public ProvFactory provFactory() {
        return new ProvFactory();
    }

    @Bean public ICpmFactory cpmFactory() {
        return new CpmMergedFactory();
    }

    @Bean public ICpmProvFactory cpmProvFactory(ProvFactory provFactory) {
        return new CpmProvFactory(provFactory);
    }

    @Bean
    public IStorage documentLoader(ProvFactory provFactory, ICpmFactory cpmFactory, ICpmProvFactory cpmProvFactory)
            throws IOException {
        IStorage storage = new Storage(provFactory, cpmFactory, cpmProvFactory);

        ObjectMapper mapper = new ObjectMapper();
        MockedAuthConfig config =
                mapper.readValue(new File("src/main/resources/mockedAuthorizationConfig.json"), MockedAuthConfig.class);

        return new MockedAuthStorage(storage, config);
    }

    @Bean public BundleQueryService bundleQueryService(IStorage documentLoader) {
        return new BundleQueryService(documentLoader);
    }
}
