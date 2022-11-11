// automatically generated by the FlatBuffers compiler, do not modify

package ee.cyber.cdoc20.fbs.recipients;

import com.google.flatbuffers.BaseVector;
import com.google.flatbuffers.ByteVector;
import com.google.flatbuffers.Constants;
import com.google.flatbuffers.FlatBufferBuilder;
import com.google.flatbuffers.Table;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

@SuppressWarnings("unused")
public final class ServerRsaDetails extends Table {
  public static void ValidateVersion() { Constants.FLATBUFFERS_2_0_8(); }
  public static ServerRsaDetails getRootAsServerRsaDetails(ByteBuffer _bb) { return getRootAsServerRsaDetails(_bb, new ServerRsaDetails()); }
  public static ServerRsaDetails getRootAsServerRsaDetails(ByteBuffer _bb, ServerRsaDetails obj) { _bb.order(ByteOrder.LITTLE_ENDIAN); return (obj.__assign(_bb.getInt(_bb.position()) + _bb.position(), _bb)); }
  public void __init(int _i, ByteBuffer _bb) { __reset(_i, _bb); }
  public ServerRsaDetails __assign(int _i, ByteBuffer _bb) { __init(_i, _bb); return this; }

  public int recipientPublicKey(int j) { int o = __offset(4); return o != 0 ? bb.get(__vector(o) + j * 1) & 0xFF : 0; }
  public int recipientPublicKeyLength() { int o = __offset(4); return o != 0 ? __vector_len(o) : 0; }
  public ByteVector recipientPublicKeyVector() { return recipientPublicKeyVector(new ByteVector()); }
  public ByteVector recipientPublicKeyVector(ByteVector obj) { int o = __offset(4); return o != 0 ? obj.__assign(__vector(o), bb) : null; }
  public ByteBuffer recipientPublicKeyAsByteBuffer() { return __vector_as_bytebuffer(4, 1); }
  public ByteBuffer recipientPublicKeyInByteBuffer(ByteBuffer _bb) { return __vector_in_bytebuffer(_bb, 4, 1); }

  public static int createServerRsaDetails(FlatBufferBuilder builder,
      int recipientPublicKeyOffset) {
    builder.startTable(1);
    ServerRsaDetails.addRecipientPublicKey(builder, recipientPublicKeyOffset);
    return ServerRsaDetails.endServerRsaDetails(builder);
  }

  public static void startServerRsaDetails(FlatBufferBuilder builder) { builder.startTable(1); }
  public static void addRecipientPublicKey(FlatBufferBuilder builder, int recipientPublicKeyOffset) { builder.addOffset(0, recipientPublicKeyOffset, 0); }
  public static int createRecipientPublicKeyVector(FlatBufferBuilder builder, byte[] data) { return builder.createByteVector(data); }
  public static int createRecipientPublicKeyVector(FlatBufferBuilder builder, ByteBuffer data) { return builder.createByteVector(data); }
  public static void startRecipientPublicKeyVector(FlatBufferBuilder builder, int numElems) { builder.startVector(1, numElems, 1); }
  public static int endServerRsaDetails(FlatBufferBuilder builder) {
    int o = builder.endTable();
    builder.required(o, 4);  // recipient_public_key
    return o;
  }

  public static final class Vector extends BaseVector {
    public Vector __assign(int _vector, int _element_size, ByteBuffer _bb) { __reset(_vector, _element_size, _bb); return this; }

    public ServerRsaDetails get(int j) { return get(new ServerRsaDetails(), j); }
    public ServerRsaDetails get(ServerRsaDetails obj, int j) {  return obj.__assign(__indirect(__element(j), bb), bb); }
  }
}
