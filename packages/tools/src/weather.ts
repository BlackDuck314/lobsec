// ── Tomorrow.io Weather Tool ─────────────────────────────────────────────────
// Fetches weather forecasts from Tomorrow.io API.

export interface WeatherConfig {
  apiKey: string;
}

export interface WeatherResult {
  location: string;
  current: {
    temperature: number;
    humidity: number;
    windSpeed: number;
    weatherCode: number;
    description: string;
  };
  daily: Array<{
    date: string;
    temperatureMax: number;
    temperatureMin: number;
    weatherCode: number;
    description: string;
  }>;
}

/** Map Tomorrow.io weather codes to human descriptions. */
const WEATHER_CODES: Record<number, string> = {
  0: "Unknown",
  1000: "Clear",
  1100: "Mostly Clear",
  1101: "Partly Cloudy",
  1102: "Mostly Cloudy",
  1001: "Cloudy",
  2000: "Fog",
  2100: "Light Fog",
  4000: "Drizzle",
  4001: "Rain",
  4200: "Light Rain",
  4201: "Heavy Rain",
  5000: "Snow",
  5001: "Flurries",
  5100: "Light Snow",
  5101: "Heavy Snow",
  6000: "Freezing Drizzle",
  6001: "Freezing Rain",
  6200: "Light Freezing Rain",
  6201: "Heavy Freezing Rain",
  7000: "Ice Pellets",
  7101: "Heavy Ice Pellets",
  7102: "Light Ice Pellets",
  8000: "Thunderstorm",
};

export function describeWeatherCode(code: number): string {
  return WEATHER_CODES[code] ?? "Unknown";
}

export async function getWeather(
  location: string,
  config: WeatherConfig,
): Promise<WeatherResult> {
  const url = new URL("https://api.tomorrow.io/v4/weather/forecast");
  url.searchParams.set("location", location);
  url.searchParams.set("apikey", config.apiKey);
  url.searchParams.set("units", "metric");

  const response = await fetch(url.toString(), {
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`Tomorrow.io API error ${response.status}: ${body}`);
  }

  const data = await response.json() as {
    location: { name?: string };
    timelines: {
      minutely?: Array<{ values: Record<string, number> }>;
      daily?: Array<{
        time: string;
        values: Record<string, number>;
      }>;
    };
  };

  const minutely = data.timelines?.minutely?.[0]?.values;
  const daily = data.timelines?.daily ?? [];

  return {
    location: data.location?.name ?? location,
    current: {
      temperature: minutely?.temperature ?? 0,
      humidity: minutely?.humidity ?? 0,
      windSpeed: minutely?.windSpeed ?? 0,
      weatherCode: minutely?.weatherCode ?? 0,
      description: describeWeatherCode(minutely?.weatherCode ?? 0),
    },
    daily: daily.slice(0, 5).map((d) => ({
      date: d.time.split("T")[0]!,
      temperatureMax: d.values.temperatureMax ?? 0,
      temperatureMin: d.values.temperatureMin ?? 0,
      weatherCode: d.values.weatherCodeMax ?? 0,
      description: describeWeatherCode(d.values.weatherCodeMax ?? 0),
    })),
  };
}

export function formatWeather(result: WeatherResult): string {
  const lines: string[] = [
    `Weather for ${result.location}:`,
    `Currently: ${result.current.description}, ${result.current.temperature}°C`,
    `Humidity: ${result.current.humidity}%, Wind: ${result.current.windSpeed} m/s`,
    "",
    "5-day forecast:",
  ];
  for (const day of result.daily) {
    lines.push(
      `  ${day.date}: ${day.description}, ${day.temperatureMin}°C – ${day.temperatureMax}°C`,
    );
  }
  return lines.join("\n");
}
