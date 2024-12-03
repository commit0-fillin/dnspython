import struct
import dns.exception
import dns.immutable
import dns.rdata
import dns.tokenizer

@dns.immutable.immutable
class GPOS(dns.rdata.Rdata):
    """GPOS record"""
    __slots__ = ['latitude', 'longitude', 'altitude']

    def __init__(self, rdclass, rdtype, latitude, longitude, altitude):
        super().__init__(rdclass, rdtype)
        if isinstance(latitude, float) or isinstance(latitude, int):
            latitude = str(latitude)
        if isinstance(longitude, float) or isinstance(longitude, int):
            longitude = str(longitude)
        if isinstance(altitude, float) or isinstance(altitude, int):
            altitude = str(altitude)
        latitude = self._as_bytes(latitude, True, 255)
        longitude = self._as_bytes(longitude, True, 255)
        altitude = self._as_bytes(altitude, True, 255)
        _validate_float_string(latitude)
        _validate_float_string(longitude)
        _validate_float_string(altitude)
        self.latitude = latitude
        self.longitude = longitude
        self.altitude = altitude
        flat = self.float_latitude
        if flat < -90.0 or flat > 90.0:
            raise dns.exception.FormError('bad latitude')
        flong = self.float_longitude
        if flong < -180.0 or flong > 180.0:
            raise dns.exception.FormError('bad longitude')

    @property
    def float_latitude(self):
        """latitude as a floating point value"""
        return float(self.latitude.decode())

    @property
    def float_longitude(self):
        """longitude as a floating point value"""
        return float(self.longitude.decode())

    @property
    def float_altitude(self):
        """altitude as a floating point value"""
        return float(self.altitude.decode())
