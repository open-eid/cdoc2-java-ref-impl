package ee.cyber.cdoc2.converter;

import java.io.File;
import java.net.FileNameMap;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.concurrent.Callable;

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "asic")
@SuppressWarnings("squid:S106")
public class CreateAsicContainerCmd implements Callable<Void> {

    private static final Logger log = LoggerFactory.getLogger(CreateAsicContainerCmd.class);

    @Option(names = {"-f", "--file" }, required = true, paramLabel = "ASIC",
        description = "the ASIC file")
    private String asicFile;

    @Parameters(paramLabel = "FILE", description = "one or more files to wrap into ASIC container",
        arity = "1..*")
    private File[] inputFiles;

    @Override
    public Void call() throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("asic --file={} {}", asicFile, Arrays.toString(inputFiles));
        }

        Container container = ContainerBuilder
            .aContainer()
            .build();

        for (File file : inputFiles) {
            FileNameMap fileNameMap = URLConnection.getFileNameMap();
            String mimeType = fileNameMap.getContentTypeFor(file.getName());
            container.addDataFile(file, mimeType);
        }

        validateContainer(container);

        container.saveAsFile(asicFile);
        return null;
    }

    private void validateContainer(Container container) {
        ContainerValidationResult result = container.validate();

        boolean isContainerValid = result.isValid();
        if (!isContainerValid) {
            throw new DigiDoc4JException("Failed to create ASIC container");
        }
    }
}
