package ee.cyber.cdoc2.container.recipients;

import com.google.flatbuffers.FlatBufferBuilder;

public interface SerializableFBS {
    /**
     *
     * @param builder FlatBuffer builder instance
     * @return offset
     */
    int serialize(FlatBufferBuilder builder);
}
