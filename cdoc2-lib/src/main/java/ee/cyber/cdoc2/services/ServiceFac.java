package ee.cyber.cdoc2.services;

@FunctionalInterface
public interface ServiceFac<S, C> {
    Service<S, C> create(ServiceConfiguration<S, C> config);
}
