// automatically generated by the FlatBuffers compiler, do not modify

package ee.cyber.cdoc20.fbs.recipients;

import com.google.flatbuffers.BaseVector;
import com.google.flatbuffers.Constants;
import com.google.flatbuffers.FlatBufferBuilder;
import com.google.flatbuffers.Table;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

@SuppressWarnings("unused")
public final class KeyServerCapsule extends Table {
  public static void ValidateVersion() { Constants.FLATBUFFERS_2_0_8(); }
  public static KeyServerCapsule getRootAsKeyServerCapsule(ByteBuffer _bb) { return getRootAsKeyServerCapsule(_bb, new KeyServerCapsule()); }
  public static KeyServerCapsule getRootAsKeyServerCapsule(ByteBuffer _bb, KeyServerCapsule obj) { _bb.order(ByteOrder.LITTLE_ENDIAN); return (obj.__assign(_bb.getInt(_bb.position()) + _bb.position(), _bb)); }
  public void __init(int _i, ByteBuffer _bb) { __reset(_i, _bb); }
  public KeyServerCapsule __assign(int _i, ByteBuffer _bb) { __init(_i, _bb); return this; }

  public byte recipientKeyDetailsType() { int o = __offset(4); return o != 0 ? bb.get(o + bb_pos) : 0; }
  public Table recipientKeyDetails(Table obj) { int o = __offset(6); return o != 0 ? __union(obj, o + bb_pos) : null; }
  public String keyserverId() { int o = __offset(8); return o != 0 ? __string(o + bb_pos) : null; }
  public ByteBuffer keyserverIdAsByteBuffer() { return __vector_as_bytebuffer(8, 1); }
  public ByteBuffer keyserverIdInByteBuffer(ByteBuffer _bb) { return __vector_in_bytebuffer(_bb, 8, 1); }
  public String transactionId() { int o = __offset(10); return o != 0 ? __string(o + bb_pos) : null; }
  public ByteBuffer transactionIdAsByteBuffer() { return __vector_as_bytebuffer(10, 1); }
  public ByteBuffer transactionIdInByteBuffer(ByteBuffer _bb) { return __vector_in_bytebuffer(_bb, 10, 1); }

  public static int createKeyServerCapsule(FlatBufferBuilder builder,
      byte recipientKeyDetailsType,
      int recipientKeyDetailsOffset,
      int keyserverIdOffset,
      int transactionIdOffset) {
    builder.startTable(4);
    KeyServerCapsule.addTransactionId(builder, transactionIdOffset);
    KeyServerCapsule.addKeyserverId(builder, keyserverIdOffset);
    KeyServerCapsule.addRecipientKeyDetails(builder, recipientKeyDetailsOffset);
    KeyServerCapsule.addRecipientKeyDetailsType(builder, recipientKeyDetailsType);
    return KeyServerCapsule.endKeyServerCapsule(builder);
  }

  public static void startKeyServerCapsule(FlatBufferBuilder builder) { builder.startTable(4); }
  public static void addRecipientKeyDetailsType(FlatBufferBuilder builder, byte recipientKeyDetailsType) { builder.addByte(0, recipientKeyDetailsType, 0); }
  public static void addRecipientKeyDetails(FlatBufferBuilder builder, int recipientKeyDetailsOffset) { builder.addOffset(1, recipientKeyDetailsOffset, 0); }
  public static void addKeyserverId(FlatBufferBuilder builder, int keyserverIdOffset) { builder.addOffset(2, keyserverIdOffset, 0); }
  public static void addTransactionId(FlatBufferBuilder builder, int transactionIdOffset) { builder.addOffset(3, transactionIdOffset, 0); }
  public static int endKeyServerCapsule(FlatBufferBuilder builder) {
    int o = builder.endTable();
    builder.required(o, 8);  // keyserver_id
    builder.required(o, 10);  // transaction_id
    return o;
  }

  public static final class Vector extends BaseVector {
    public Vector __assign(int _vector, int _element_size, ByteBuffer _bb) { __reset(_vector, _element_size, _bb); return this; }

    public KeyServerCapsule get(int j) { return get(new KeyServerCapsule(), j); }
    public KeyServerCapsule get(KeyServerCapsule obj, int j) {  return obj.__assign(__indirect(__element(j), bb), bb); }
  }
}
