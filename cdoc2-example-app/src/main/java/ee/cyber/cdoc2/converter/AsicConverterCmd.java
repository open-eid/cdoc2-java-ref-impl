package ee.cyber.cdoc2.converter;

import ee.cyber.cdoc2.converter.util.CommonService;
import ee.cyber.cdoc2.converter.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "asic-convert")
@SuppressWarnings("squid:S106")
public class AsicConverterCmd implements Callable<Void> {

    private static final Logger log = LoggerFactory.getLogger(AsicConverterCmd.class);

    @Option(names = {"-f", "-a", "--asic" }, required = true,
        paramLabel = "ASIC", description = "the ASIC file")
    File asicFile;

    @Option(names = {"-o", "--out", "--cdoc2"}, required = false,
        paramLabel = "CDOC2", description = "the CDOC2 file")
    File cdoc2FileOption;

    @Option(names = { "--tmp"}, required = false,
        paramLabel = "DIR",
        description = "temp directory used for temporary files extracted from ASIC container")
    Path tempDir = null;

    @Option(names= {"--label"}, required = false,
        paramLabel = "label", description = "cdoc2 recipient label")
    String labelOption;

    @Option(names = { "-h", "--help" }, usageHelp = false, description = "display a help message")
    private boolean helpRequested = false;

    @Override
    public Void call() throws Exception {

        char[] password = CommonService.askPassword();
        String label = CommonService.getLabel(labelOption);

        File cdoc2File = CommonService.getCdoc2File(cdoc2FileOption, asicFile);

        if (!asicFile.getPath().contains(".asic")) {
            throw new CommandLine.TypeConversionException(
                "Missing required file extension .asice for conversion"
            );
        }

        encrypt(cdoc2File, asicFile, label, password);
        System.out.println("Created cdoc2 " + cdoc2File.getAbsolutePath());

        return null;
    }

    private void encrypt(File cdoc2OutFile, File incomingFile, String label, char[] password)
        throws Exception{

        Container container = ContainerOpener.open(incomingFile.getPath());
        ContainerValidationResult result = container.validate();

        boolean isContainerValid = result.isValid();
        if (!isContainerValid) {
            Util.encrypt(cdoc2OutFile, List.of(incomingFile), label, password);
            return;
        }

        List<File> extractedFiles = checkSignatureOrExtractFiles(container, incomingFile);
        Util.encrypt(cdoc2OutFile, extractedFiles, label, password);
    }

    private List<File> checkSignatureOrExtractFiles(
        Container container,
        File incomingFile
    ) {
        if (!container.getSignatures().isEmpty()) {
            return List.of(incomingFile);
        } else {
            List<DataFile> dataFiles = container.getDataFiles();
            List<File> extractedFiles = new ArrayList<>();
            for (DataFile dataFile : dataFiles) {
                String incomingFilePath = incomingFile.getPath();
                String outFilePath =
                    incomingFilePath.substring(0, incomingFilePath.lastIndexOf("/") + 1);
                String extractedFile = outFilePath + "/" + dataFile.getName();
                dataFile.saveAs(extractedFile);
                extractedFiles.add(new File(extractedFile));
            }
            return extractedFiles;
        }
    }
}
