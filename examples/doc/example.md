# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [Booking.proto](#Booking.proto)
    - [Booking](#com.example.Booking)
    - [BookingStatus](#com.example.BookingStatus)
    - [BookingStatusID](#com.example.BookingStatusID)
    - [EmptyBookingMessage](#com.example.EmptyBookingMessage)
  
    - [BookingService](#com.example.BookingService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="Booking.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## Booking.proto



<a name="com.example.Booking"></a>

### Booking
Represents the booking of a vehicle.&lt;br/&gt;&lt;br/&gt;Vehicles are some cool shit. But drive carefully!


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| vehicle_id | [int32](#int32) |  | ID of booked vehicle. |
| customer_id | [int32](#int32) |  | Customer that booked the vehicle. |
| status | [BookingStatus](#com.example.BookingStatus) |  | Status of the booking. |
| confirmation_sent | [bool](#bool) |  | Has booking confirmation been sent? |
| payment_received | [bool](#bool) |  | Has payment been received? |






<a name="com.example.BookingStatus"></a>

### BookingStatus
Represents the status of a vehicle booking.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [int32](#int32) |  | Unique booking status ID. |
| description | [string](#string) |  | Booking status description. E.g. &#34;Active&#34;. |






<a name="com.example.BookingStatusID"></a>

### BookingStatusID
Represents the booking status ID.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |






<a name="com.example.EmptyBookingMessage"></a>

### EmptyBookingMessage
An empty message for testing





 

 

 


<a name="com.example.BookingService"></a>

### BookingService
Service for handling vehicle bookings.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| BookVehicle | [Booking](#com.example.Booking) | [BookingStatus](#com.example.BookingStatus) | Used to book a vehicle. Pass in a Booking and a BookingStatus will be returned. |
| BookingUpdates | [BookingStatusID](#com.example.BookingStatusID) | [BookingStatus](#com.example.BookingStatus) stream | Used to subscribe to updates of the BookingStatus. |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |
