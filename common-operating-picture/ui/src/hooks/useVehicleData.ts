import { useState, useCallback, useEffect, useMemo, useContext, useRef } from 'react';
import { useRpcClient } from '@/hooks/useRpcClient';
import { BannerContext } from '@/contexts/BannerContext';
import { TimestampSelector } from '@/proto/tdf_object/v1/tdf_object_pb';
import { SrcType } from '@/proto/tdf_object/v1/tdf_object_pb';
import { Timestamp } from '@bufbuild/protobuf';
import { VehicleData } from '@/types/vehicle';
import dayjs from 'dayjs';

const VEHICLE_SRC_TYPE_ID = 'vehicles';
const POLL_INTERVAL_MS = 5_000;

export function useVehicleData() {
  const { getSrcType, queryTdfObjectsLight } = useRpcClient();
  const { activeEntitlements } = useContext(BannerContext);

  const [vehicleData, setVehicleData] = useState<VehicleData[]>([]);
  const [vehicleSrcType, setVehicleSrcType] = useState<SrcType>();

  const filteredVehicleData = useMemo(() => {
    if (!activeEntitlements || activeEntitlements.size === 0 || activeEntitlements.has('NoAccess')) {
      return vehicleData;
    }

    return vehicleData.filter((vehicle) => {
      const classification = vehicle.data?.attrClassification;
      if (!classification) return true;
      const classStr = Array.isArray(classification) ? classification[0] : classification;
      return classStr ? activeEntitlements.has(classStr) : true;
    });
  }, [vehicleData, activeEntitlements]);

  const fetchVehicles = useCallback(async () => {
    try {
      const tsRange = new TimestampSelector();
      tsRange.greaterOrEqualTo = Timestamp.fromDate(dayjs().subtract(24, 'hour').toDate());

      const response = await queryTdfObjectsLight({
        srcType: VEHICLE_SRC_TYPE_ID,
        tsRange,
      });

      const transformed: VehicleData[] = response
        .filter((o) => o.geo)
        .map((o) => {
          const geoJson = JSON.parse(o.geo);
          const [lng, lat] = geoJson.coordinates;

          let telemetry = {};
          try {
            if (o.metadata && o.metadata !== 'null') telemetry = JSON.parse(o.metadata);
          } catch (e) {
            console.error('Metadata parse error', e);
          }

          let attributes = {};
          try {
            if (o.search && o.search !== 'null') attributes = JSON.parse(o.search);
          } catch (e) {
            console.error('Search field parse error', e);
          }

          return {
            id: o.id,
            pos: { lat, lng },
            rawObject: o,
            data: { ...telemetry, ...attributes },
          };
        });

      setVehicleData(transformed);
    } catch (error) {
      console.error('Error fetching vehicles:', error);
      setVehicleData([]);
    }
  }, [queryTdfObjectsLight]);

  // Keep a ref to the latest fetchVehicles so the interval never needs to reset.
  const fetchVehiclesRef = useRef(fetchVehicles);
  useEffect(() => {
    fetchVehiclesRef.current = fetchVehicles;
  }, [fetchVehicles]);

  // Fetch vehicle source type schema once
  useEffect(() => {
    if (vehicleSrcType) return;

    const fetchSchema = async () => {
      try {
        const { srcType } = await getSrcType({ srcType: VEHICLE_SRC_TYPE_ID });
        setVehicleSrcType(srcType);
      } catch (err) {
        console.error('Failed to fetch vehicle source type schema', err);
      }
    };

    fetchSchema();
  }, [getSrcType, vehicleSrcType]);

  // Initial fetch + stable poll — empty deps so the interval is set once on
  // mount and never cleared/reset when fetchVehicles changes reference.
  useEffect(() => {
    fetchVehiclesRef.current();
    const intervalId = setInterval(() => fetchVehiclesRef.current(), POLL_INTERVAL_MS);
    return () => clearInterval(intervalId);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    filteredVehicleData,
    vehicleSrcType,
    fetchVehicles,
  };
}
