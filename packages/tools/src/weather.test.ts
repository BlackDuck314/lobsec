import { describe, it, expect } from "vitest";
import { describeWeatherCode, formatWeather, type WeatherResult } from "./weather.js";

describe("Weather", () => {
  describe("describeWeatherCode", () => {
    it("maps known weather codes", () => {
      expect(describeWeatherCode(1000)).toBe("Clear");
      expect(describeWeatherCode(4001)).toBe("Rain");
      expect(describeWeatherCode(8000)).toBe("Thunderstorm");
      expect(describeWeatherCode(5000)).toBe("Snow");
    });

    it("returns Unknown for unmapped codes", () => {
      expect(describeWeatherCode(9999)).toBe("Unknown");
      expect(describeWeatherCode(0)).toBe("Unknown");
    });
  });

  describe("formatWeather", () => {
    it("formats a complete weather result", () => {
      const result: WeatherResult = {
        location: "London",
        current: {
          temperature: 18.5,
          humidity: 65,
          windSpeed: 3.2,
          weatherCode: 1100,
          description: "Mostly Clear",
        },
        daily: [
          { date: "2026-02-27", temperatureMax: 20, temperatureMin: 12, weatherCode: 1100, description: "Mostly Clear" },
          { date: "2026-02-28", temperatureMax: 19, temperatureMin: 11, weatherCode: 4001, description: "Rain" },
        ],
      };

      const formatted = formatWeather(result);
      expect(formatted).toContain("London");
      expect(formatted).toContain("18.5°C");
      expect(formatted).toContain("Mostly Clear");
      expect(formatted).toContain("65%");
      expect(formatted).toContain("3.2 m/s");
      expect(formatted).toContain("2026-02-27");
      expect(formatted).toContain("12°C – 20°C");
      expect(formatted).toContain("Rain");
    });

    it("handles empty daily forecast", () => {
      const result: WeatherResult = {
        location: "Test",
        current: { temperature: 0, humidity: 0, windSpeed: 0, weatherCode: 0, description: "Unknown" },
        daily: [],
      };
      const formatted = formatWeather(result);
      expect(formatted).toContain("Test");
      expect(formatted).toContain("5-day forecast:");
    });
  });
});
