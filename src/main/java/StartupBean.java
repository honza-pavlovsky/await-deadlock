import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.alerts.LOTLAlert;
import eu.europa.esig.dss.tsl.alerts.TLAlert;
import eu.europa.esig.dss.tsl.alerts.detections.LOTLLocationChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.OJUrlChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLExpirationDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogLOTLLocationChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogOJUrlChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLExpirationAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLSignatureErrorAlertHandler;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import io.quarkus.runtime.StartupEvent;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.Executors;

@ApplicationScoped
public class StartupBean {
    private static Log log = LogFactory.getLog(StartupBean.class);
    private static final String LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
    private static final String OJ_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG";

    public void init(@Observes StartupEvent ev) {
        log.info("Initializing cache");
        getCommonCertificateVerifier();
    }

    public CommonCertificateVerifier getCommonCertificateVerifier() {
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        TLValidationJob job = job();
        TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
        job.setTrustedListCertificateSource(trustedListsCertificateSource);
        job.onlineRefresh();
        commonCertificateVerifier.setTrustedCertSources(trustedListsCertificateSource);
        CommonsDataLoader commonsDataLoader = new CommonsDataLoader();
        commonCertificateVerifier.setCrlSource(new OnlineCRLSource());
        commonCertificateVerifier.setOcspSource(new OnlineOCSPSource());
        commonCertificateVerifier.setDataLoader(commonsDataLoader);
        return commonCertificateVerifier;
    }

    @Deprecated
    public static TLValidationJob job() {
        return job(false, false, null, 0, null, null);
    }

    public static TLValidationJob job(boolean httpProxy, boolean httpsProxy, String host, int port, String user, String password) {
        TLValidationJob job = new TLValidationJob();
        job.setOfflineDataLoader(offlineLoader());
        job.setOnlineDataLoader(onlineLoader(httpProxy, httpsProxy, host, port, user, password));
        job.setTrustedListCertificateSource(trustedCertificateSource());
        job.setSynchronizationStrategy(new AcceptAllStrategy());
        job.setCacheCleaner(cacheCleaner());
        LOTLSource europeanLOTL = europeanLOTL();
        job.setListOfTrustedListSources(europeanLOTL);
        job.setLOTLAlerts(Arrays.asList(ojUrlAlert(europeanLOTL), lotlLocationAlert(europeanLOTL)));
        job.setTLAlerts(Arrays.asList(tlSigningAlert(), tlExpirationDetection()));
        return job;
    }

    public static DSSFileLoader onlineLoader(boolean httpProxy, boolean httpsProxy, String host, int port, String user, String password) {
        ProxyConfig proxyConfig = getProxyConfig(httpProxy, httpsProxy, host, port, user, password);
        FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        onlineFileLoader.setDataLoader(new CommonsDataLoader());
        onlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
        return onlineFileLoader;
    }

    public static TrustedListsCertificateSource trustedCertificateSource() {
        return new TrustedListsCertificateSource();
    }

    public static LOTLSource europeanLOTL() {
        LOTLSource lotlSource = new LOTLSource();
        lotlSource.setUrl(LOTL_URL);
        lotlSource.setCertificateSource(new CommonCertificateSource());
        lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(OJ_URL));
        lotlSource.setPivotSupport(true);
        return lotlSource;
    }

    public CertificateSource officialJournalContentKeyStore() {
        try {
            return new KeyStoreCertificateSource(new File("src/main/resources/keystore.p12"), "PKCS12", "dss-password");
        } catch (IOException e) {
            throw new DSSException("Unable to load the keystore", e);
        }
    }

    public static DSSFileLoader offlineLoader() {
        FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
        offlineFileLoader.setDataLoader(new IgnoreDataLoader());
        offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
        return offlineFileLoader;
    }

    public static File tlCacheDirectory() {
        File rootFolder = new File(System.getProperty("java.io.tmpdir"));
        File tslCache = new File(rootFolder, "dss-tsl-loader");
        if (tslCache.mkdirs()) {
            System.out.println("TL Cache folder : " + tslCache.getAbsolutePath());
        }
        return tslCache;
    }

    public static CommonsDataLoader dataLoader() {
        return new CommonsDataLoader();
    }

    public static CacheCleaner cacheCleaner() {
        CacheCleaner cacheCleaner = new CacheCleaner();
        cacheCleaner.setCleanMemory(true);
        cacheCleaner.setCleanFileSystem(true);
        cacheCleaner.setDSSFileLoader(offlineLoader());
        return cacheCleaner;
    }

    // Optionally : alerting.
    // Recommended detections : OJUrlChangeDetection + LOTLLocationChangeDetection

    public static TLAlert tlSigningAlert() {
        TLSignatureErrorDetection signingDetection = new TLSignatureErrorDetection();
        LogTLSignatureErrorAlertHandler handler = new LogTLSignatureErrorAlertHandler();
        return new TLAlert(signingDetection, handler);
    }

    public static TLAlert tlExpirationDetection() {
        TLExpirationDetection expirationDetection = new TLExpirationDetection();
        LogTLExpirationAlertHandler handler = new LogTLExpirationAlertHandler();
        return new TLAlert(expirationDetection, handler);
    }

    public static LOTLAlert ojUrlAlert(LOTLSource source) {
        OJUrlChangeDetection ojUrlDetection = new OJUrlChangeDetection(source);
        LogOJUrlChangeAlertHandler handler = new LogOJUrlChangeAlertHandler();
        return new LOTLAlert(ojUrlDetection, handler);
    }

    public static LOTLAlert lotlLocationAlert(LOTLSource source) {
        LOTLLocationChangeDetection lotlLocationDetection = new LOTLLocationChangeDetection(source);
        LogLOTLLocationChangeAlertHandler handler = new LogLOTLLocationChangeAlertHandler();
        return new LOTLAlert(lotlLocationDetection, handler);
    }

    private static ProxyConfig getProxyConfig(boolean httpProxy, boolean httpsProxy, String host, int port, String user, String password) {
        ProxyConfig proxyConfig = new ProxyConfig();
        if (httpProxy) {
            ProxyProperties httpProps = new ProxyProperties();
            httpProps.setHost(host);
            httpProps.setPort(port);
            httpProps.setUser(user);
            httpProps.setPassword(password);
            proxyConfig.setHttpProperties(httpProps);
        }

        if (httpsProxy) {
            ProxyProperties httpsProps = new ProxyProperties();
            proxyConfig.setHttpsProperties(httpsProps);
            httpsProps.setHost(host);
            httpsProps.setPort(port);
            httpsProps.setUser(user);
            httpsProps.setPassword(password);
            proxyConfig.setHttpsProperties(httpsProps);
        }
        return proxyConfig;
    }
}
