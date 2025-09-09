send("Script start loading");

const countryProfiles = {
    'Brazil': {
        locale: 'pt-BR',
        country: 'BR',
        langCode: 'pt',
        timezone: 'America/Sao_Paulo',
        displayLang: 'Portuguese',
        mcc_mnc: '72402',
        mcc: 724,
        mnc: 2,
        operatorName: 'TIM',
        mockLocationData: {
            latitude: -23.5500,
            longitude: -46.6333,
            city: 'São Paulo',
            accuracy: 10.0,
            altitude: 760.0,
            verticalAccuracy: 5.0,
            speed: 15.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 750.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'United States': {
        locale: 'en-US',
        country: 'US',
        langCode: 'en',
        timezone: 'America/New_York',
        displayLang: 'English',
        mcc_mnc: '310410',
        mcc: 310,
        mnc: 410,
        operatorName: 'AT&T',
        mockLocationData: {
            latitude: 39.9067,
            longitude: -77.0366,
            city: 'Washington, D.C.',
            accuracy: 5.0,
            altitude: 100.0,
            verticalAccuracy: 2.5,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 95.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'India': {
        locale: 'hi-IN',
        country: 'IN',
        langCode: 'hi',
        timezone: 'Asia/Kolkata',
        displayLang: 'Hindi',
        mcc_mnc: '40431',
        mcc: 404,
        mnc: 31,
        operatorName: 'Jio',
        mockLocationData: {
            latitude: 28.7041,
            longitude: 77.1025,
            city: 'Delhi',
            accuracy: 12.0,
            altitude: 216.0,
            verticalAccuracy: 6.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 210.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'Turkey': {
        locale: 'tr-TR',
        country: 'TR',
        langCode: 'tr',
        timezone: 'Europe/Istanbul',
        displayLang: 'Turkish',
        mcc_mnc: '28601',
        mcc: 286,
        mnc: 1,
        operatorName: 'Turkcell',
        mockLocationData: {
            latitude: 38.9637,
            longitude: 35.2433,
            city: 'Ankara',
            accuracy: 8.0,
            altitude: 938.0,
            verticalAccuracy: 4.0,
            speed: 20.0,
            speedAccuracy: 4.0,
            meanSeaLevel: 930.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Ukraine': {
        locale: 'uk-UA',
        country: 'UA',
        langCode: 'uk',
        timezone: 'Europe/Kiev',
        displayLang: 'Ukrainian',
        mcc_mnc: '25501',
        mcc: 255,
        mnc: 1,
        operatorName: 'Kyivstar',
        mockLocationData: {
            latitude: 50.4501,
            longitude: 30.5234,
            city: 'Kyiv',
            accuracy: 7.0,
            altitude: 179.0,
            verticalAccuracy: 3.5,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 175.0,
            meanSeaLevelAccuracy: 3.0
        }
    },
    'Indonesia': {
        locale: 'id-ID',
        country: 'ID',
        langCode: 'id',
        timezone: 'Asia/Jakarta',
        displayLang: 'Indonesian',
        mcc_mnc: '51010',
        mcc: 510,
        mnc: 10,
        operatorName: 'Telkomsel',
        mockLocationData: {
            latitude: -6.2088,
            longitude: 106.8456,
            city: 'Jakarta',
            accuracy: 9.0,
            altitude: 7.0,
            verticalAccuracy: 2.0,
            speed: 5.0,
            speedAccuracy: 1.0,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Thailand': {
        locale: 'th-TH',
        country: 'TH',
        langCode: 'th',
        timezone: 'Asia/Bangkok',
        displayLang: 'Thai',
        mcc_mnc: '52003',
        mcc: 520,
        mnc: 3,
        operatorName: 'AIS',
        mockLocationData: {
            latitude: 13.7563,
            longitude: 100.5018,
            city: 'Bangkok',
            accuracy: 6.0,
            altitude: 1.5,
            verticalAccuracy: 1.0,
            speed: 10.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 0.5,
            meanSeaLevelAccuracy: 0.8
        }
    },
    'UAE': {
        locale: 'ar-AE',
        country: 'AE',
        langCode: 'ar',
        timezone: 'Asia/Dubai',
        displayLang: 'Arabic',
        mcc_mnc: '42402',
        mcc: 424,
        mnc: 2,
        operatorName: 'Etisalat',
        mockLocationData: {
            latitude: 25.276987,
            longitude: 55.296249,
            city: 'Dubai',
            accuracy: 4.0,
            altitude: 66.0,
            verticalAccuracy: 1.5,
            speed: 25.0,
            speedAccuracy: 5.0,
            meanSeaLevel: 60.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'United Kingdom': {
        locale: 'en-GB',
        country: 'GB',
        langCode: 'en',
        timezone: 'Europe/London',
        displayLang: 'English',
        mcc_mnc: '23410',
        mcc: 234,
        mnc: 10,
        operatorName: 'O2',
        mockLocationData: {
            latitude: 51.5072,
            longitude: -0.1275,
            city: 'London',
            accuracy: 3.0,
            altitude: 35.0,
            verticalAccuracy: 1.2,
            speed: 8.0,
            speedAccuracy: 1.0,
            meanSeaLevel: 30.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Saudi Arabia': {
        locale: 'ar-SA',
        country: 'SA',
        langCode: 'ar',
        timezone: 'Asia/Riyadh',
        displayLang: 'Arabic',
        mcc_mnc: '42001',
        mcc: 420,
        mnc: 1,
        operatorName: 'STC',
        mockLocationData: {
            latitude: 24.6333,
            longitude: 46.7167,
            city: 'Riyadh',
            accuracy: 9.0,
            altitude: 600.0,
            verticalAccuracy: 4.5,
            speed: 22.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 590.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Austria': {
        locale: 'de-AT',
        country: 'AT',
        langCode: 'de',
        timezone: 'Europe/Vienna',
        displayLang: 'German',
        mcc_mnc: '23201',
        mcc: 232,
        mnc: 1,
        operatorName: 'A1',
        mockLocationData: {
            latitude: 48.2083,
            longitude: 16.3725,
            city: 'Vienna',
            accuracy: 6.0,
            altitude: 180.0,
            verticalAccuracy: 3.0,
            speed: 18.0,
            speedAccuracy: 2.8,
            meanSeaLevel: 175.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Malaysia': {
        locale: 'ms-MY',
        country: 'MY',
        langCode: 'ms',
        timezone: 'Asia/Kuala_Lumpur',
        displayLang: 'Malay',
        mcc_mnc: '50219',
        mcc: 502,
        mnc: 19,
        operatorName: 'Celcom',
        mockLocationData: {
            latitude: 3.1390,
            longitude: 101.6869,
            city: 'Kuala Lumpur',
            accuracy: 8.0,
            altitude: 80.0,
            verticalAccuracy: 3.8,
            speed: 12.0,
            speedAccuracy: 2.2,
            meanSeaLevel: 75.0,
            meanSeaLevelAccuracy: 3.0
        }
    },
    'Pakistan': {
        locale: 'ur-PK',
        country: 'PK',
        langCode: 'ur',
        timezone: 'Asia/Karachi',
        displayLang: 'Urdu',
        mcc_mnc: '41001',
        mcc: 410,
        mnc: 1,
        operatorName: 'Jazz',
        mockLocationData: {
            latitude: 24.8600,
            longitude: 67.0100,
            city: 'Karachi',
            accuracy: 15.0,
            altitude: 8.0,
            verticalAccuracy: 4.2,
            speed: 7.0,
            speedAccuracy: 1.8,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Kazakhstan': {
        locale: 'kk-KZ',
        country: 'KZ',
        langCode: 'kk',
        timezone: 'Asia/Almaty',
        displayLang: 'Kazakh',
        mcc_mnc: '40101',
        mcc: 401,
        mnc: 1,
        operatorName: 'Beeline',
        mockLocationData: {
            latitude: 43.2389,
            longitude: 76.8897,
            city: 'Almaty',
            accuracy: 11.0,
            altitude: 780.0,
            verticalAccuracy: 5.5,
            speed: 18.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 770.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Iran': {
        locale: 'fa-IR',
        country: 'IR',
        langCode: 'fa',
        timezone: 'Asia/Tehran',
        displayLang: 'Persian',
        mcc_mnc: '43211',
        mcc: 432,
        mnc: 11,
        operatorName: 'Mobile Telecommunication Company of Iran (MCI)',
        mockLocationData: {
            latitude: 35.6892,
            longitude: 51.3890,
            city: 'Tehran',
            accuracy: 13.0,
            altitude: 1200.0,
            verticalAccuracy: 6.5,
            speed: 14.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 1190.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'Russia': {
        locale: 'ru-RU',
        country: 'RU',
        langCode: 'ru',
        timezone: 'Europe/Moscow',
        displayLang: 'Russian',
        mcc_mnc: '25001',
        mcc: 250,
        mnc: 1,
        operatorName: 'MTS',
        mockLocationData: {
            latitude: 55.7558,
            longitude: 37.6172,
            city: 'Moscow',
            accuracy: 7.0,
            altitude: 156.0,
            verticalAccuracy: 3.2,
            speed: 20.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 150.0,
            meanSeaLevelAccuracy: 2.8
        }
    },
    'Japan': {
        locale: 'ja-JP',
        country: 'JP',
        langCode: 'ja',
        timezone: 'Asia/Tokyo',
        displayLang: 'Japanese',
        mcc_mnc: '44010',
        mcc: 440,
        mnc: 10,
        operatorName: 'Docomo',
        mockLocationData: {
            latitude: 35.6895,
            longitude: 139.6917,
            city: 'Tokyo',
            accuracy: 5.0,
            altitude: 40.0,
            verticalAccuracy: 2.0,
            speed: 18.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 35.0,
            meanSeaLevelAccuracy: 1.8
        }
    },
    'China': {
        locale: 'zh-CN',
        country: 'CN',
        langCode: 'zh',
        timezone: 'Asia/Shanghai',
        displayLang: 'Chinese',
        mcc_mnc: '46000',
        mcc: 460,
        mnc: 0,
        operatorName: 'China Mobile',
        mockLocationData: {
            latitude: 31.2304,
            longitude: 121.4737,
            city: 'Shanghai',
            accuracy: 8.0,
            altitude: 4.0,
            verticalAccuracy: 1.5,
            speed: 15.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 2.0,
            meanSeaLevelAccuracy: 1.2
        }
    },
    'Nigeria': {
        locale: 'en-NG',
        country: 'NG',
        langCode: 'en',
        timezone: 'Africa/Lagos',
        displayLang: 'English',
        mcc_mnc: '62120',
        mcc: 621,
        mnc: 20,
        operatorName: 'Airtel Nigeria',
        mockLocationData: {
            latitude: 9.0765,
            longitude: 7.3986,
            city: 'Abuja',
            accuracy: 15.0,
            altitude: 360.0,
            verticalAccuracy: 7.0,
            speed: 10.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 350.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Bangladesh': {
        locale: 'bn-BD',
        country: 'BD',
        langCode: 'bn',
        timezone: 'Asia/Dhaka',
        displayLang: 'Bengali',
        mcc_mnc: '47001',
        mcc: 470,
        mnc: 1,
        operatorName: 'Grameenphone',
        mockLocationData: {
            latitude: 23.8103,
            longitude: 90.4125,
            city: 'Dhaka',
            accuracy: 10.0,
            altitude: 8.0,
            verticalAccuracy: 4.5,
            speed: 5.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Mexico': {
        locale: 'es-MX',
        country: 'MX',
        langCode: 'es',
        timezone: 'America/Mexico_City',
        displayLang: 'Spanish',
        mcc_mnc: '334020',
        mcc: 334,
        mnc: 20,
        operatorName: 'Telcel',
        mockLocationData: {
            latitude: 19.4326,
            longitude: -99.1332,
            city: 'Mexico City',
            accuracy: 12.0,
            altitude: 2240.0,
            verticalAccuracy: 6.0,
            speed: 15.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 2230.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'Philippines': {
        locale: 'en-PH',
        country: 'PH',
        langCode: 'en',
        timezone: 'Asia/Manila',
        displayLang: 'English',
        mcc_mnc: '51502',
        mcc: 515,
        mnc: 2,
        operatorName: 'Globe',
        mockLocationData: {
            latitude: 14.5995,
            longitude: 120.9842,
            city: 'Manila',
            accuracy: 9.0,
            altitude: 16.0,
            verticalAccuracy: 4.0,
            speed: 10.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 10.0,
            meanSeaLevelAccuracy: 3.0
        }
    },
    'Egypt': {
        locale: 'ar-EG',
        country: 'EG',
        langCode: 'ar',
        timezone: 'Africa/Cairo',
        displayLang: 'Arabic',
        mcc_mnc: '60201',
        mcc: 602,
        mnc: 1,
        operatorName: 'Vodafone Egypt',
        mockLocationData: {
            latitude: 30.0444,
            longitude: 31.2357,
            city: 'Cairo',
            accuracy: 10.0,
            altitude: 20.0,
            verticalAccuracy: 5.0,
            speed: 12.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 15.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Vietnam': {
        locale: 'vi-VN',
        country: 'VN',
        langCode: 'vi',
        timezone: 'Asia/Ho_Chi_Minh',
        displayLang: 'Vietnamese',
        mcc_mnc: '45202',
        mcc: 452,
        mnc: 2,
        operatorName: 'Vinaphone',
        mockLocationData: {
            latitude: 10.7626,
            longitude: 106.6601,
            city: 'Ho Chi Minh City',
            accuracy: 8.0,
            altitude: 9.0,
            verticalAccuracy: 3.5,
            speed: 6.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Germany': {
        locale: 'de-DE',
        country: 'DE',
        langCode: 'de',
        timezone: 'Europe/Berlin',
        displayLang: 'German',
        mcc_mnc: '26201',
        mcc: 262,
        mnc: 1,
        operatorName: 'Deutsche Telekom',
        mockLocationData: {
            latitude: 52.5200,
            longitude: 13.4050,
            city: 'Berlin',
            accuracy: 5.0,
            altitude: 34.0,
            verticalAccuracy: 2.0,
            speed: 15.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 30.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'France': {
        locale: 'fr-FR',
        country: 'FR',
        langCode: 'fr',
        timezone: 'Europe/Paris',
        displayLang: 'French',
        mcc_mnc: '20810',
        mcc: 208,
        mnc: 10,
        operatorName: 'Orange',
        mockLocationData: {
            latitude: 48.8566,
            longitude: 2.3522,
            city: 'Paris',
            accuracy: 4.0,
            altitude: 35.0,
            verticalAccuracy: 1.8,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 30.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Italy': {
        locale: 'it-IT',
        country: 'IT',
        langCode: 'it',
        timezone: 'Europe/Rome',
        displayLang: 'Italian',
        mcc_mnc: '22210',
        mcc: 222,
        mnc: 10,
        operatorName: 'Vodafone Italy',
        mockLocationData: {
            latitude: 41.9028,
            longitude: 12.4964,
            city: 'Rome',
            accuracy: 7.0,
            altitude: 20.0,
            verticalAccuracy: 3.0,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 15.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'South Korea': {
        locale: 'ko-KR',
        country: 'KR',
        langCode: 'ko',
        timezone: 'Asia/Seoul',
        displayLang: 'Korean',
        mcc_mnc: '45005',
        mcc: 450,
        mnc: 5,
        operatorName: 'SK Telecom',
        mockLocationData: {
            latitude: 37.5665,
            longitude: 126.9780,
            city: 'Seoul',
            accuracy: 5.0,
            altitude: 87.0,
            verticalAccuracy: 2.2,
            speed: 18.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 85.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Spain': {
        locale: 'es-ES',
        country: 'ES',
        langCode: 'es',
        timezone: 'Europe/Madrid',
        displayLang: 'Spanish',
        mcc_mnc: '21407',
        mcc: 214,
        mnc: 7,
        operatorName: 'Movistar',
        mockLocationData: {
            latitude: 40.4168,
            longitude: -3.7038,
            city: 'Madrid',
            accuracy: 6.0,
            altitude: 667.0,
            verticalAccuracy: 2.8,
            speed: 14.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 660.0,
            meanSeaLevelAccuracy: 3.0
        }
    },
    'Argentina': {
        locale: 'es-AR',
        country: 'AR',
        langCode: 'es',
        timezone: 'America/Argentina/Buenos_Aires',
        displayLang: 'Spanish',
        mcc_mnc: '722070',
        mcc: 722,
        mnc: 70,
        operatorName: 'Movistar Argentina',
        mockLocationData: {
            latitude: -34.6037,
            longitude: -58.3816,
            city: 'Buenos Aires',
            accuracy: 10.0,
            altitude: 25.0,
            verticalAccuracy: 4.5,
            speed: 9.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 20.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Colombia': {
        locale: 'es-CO',
        country: 'CO',
        langCode: 'es',
        timezone: 'America/Bogota',
        displayLang: 'Spanish',
        mcc_mnc: '732101',
        mcc: 732,
        mnc: 101,
        operatorName: 'Claro Colombia',
        mockLocationData: {
            latitude: 4.7110,
            longitude: -74.0721,
            city: 'Bogotá',
            accuracy: 12.0,
            altitude: 2640.0,
            verticalAccuracy: 6.0,
            speed: 8.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 2630.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'Iraq': {
        locale: 'ar-IQ',
        country: 'IQ',
        langCode: 'ar',
        timezone: 'Asia/Baghdad',
        displayLang: 'Arabic',
        mcc_mnc: '41805',
        mcc: 418,
        mnc: 5,
        operatorName: 'Zain',
        mockLocationData: {
            latitude: 33.3152,
            longitude: 44.3661,
            city: 'Baghdad',
            accuracy: 15.0,
            altitude: 34.0,
            verticalAccuracy: 7.0,
            speed: 10.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 30.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Sudan': {
        locale: 'ar-SD',
        country: 'SD',
        langCode: 'ar',
        timezone: 'Africa/Khartoum',
        displayLang: 'Arabic',
        mcc_mnc: '63407',
        mcc: 634,
        mnc: 7,
        operatorName: 'MTN Sudan',
        mockLocationData: {
            latitude: 15.5000,
            longitude: 32.5500,
            city: 'Khartoum',
            accuracy: 18.0,
            altitude: 380.0,
            verticalAccuracy: 8.0,
            speed: 10.0,
            speedAccuracy: 4.0,
            meanSeaLevel: 375.0,
            meanSeaLevelAccuracy: 5.5
        }
    },
    'Algeria': {
        locale: 'ar-DZ',
        country: 'DZ',
        langCode: 'ar',
        timezone: 'Africa/Algiers',
        displayLang: 'Arabic',
        mcc_mnc: '60301',
        mcc: 603,
        mnc: 1,
        operatorName: 'Djezzy',
        mockLocationData: {
            latitude: 36.7538,
            longitude: 3.0588,
            city: 'Algiers',
            accuracy: 11.0,
            altitude: 20.0,
            verticalAccuracy: 5.5,
            speed: 15.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 15.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Canada': {
        locale: 'en-CA',
        country: 'CA',
        langCode: 'en',
        timezone: 'America/Toronto',
        displayLang: 'English',
        mcc_mnc: '302610',
        mcc: 302,
        mnc: 610,
        operatorName: 'Rogers',
        mockLocationData: {
            latitude: 43.6532,
            longitude: -79.3832,
            city: 'Toronto',
            accuracy: 6.0,
            altitude: 76.0,
            verticalAccuracy: 2.5,
            speed: 18.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 70.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Poland': {
        locale: 'pl-PL',
        country: 'PL',
        langCode: 'pl',
        timezone: 'Europe/Warsaw',
        displayLang: 'Polish',
        mcc_mnc: '26002',
        mcc: 260,
        mnc: 2,
        operatorName: 'T-Mobile Polska',
        mockLocationData: {
            latitude: 52.2297,
            longitude: 21.0122,
            city: 'Warsaw',
            accuracy: 7.0,
            altitude: 100.0,
            verticalAccuracy: 3.0,
            speed: 15.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 95.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Morocco': {
        locale: 'fr-MA',
        country: 'MA',
        langCode: 'fr',
        timezone: 'Africa/Casablanca',
        displayLang: 'French',
        mcc_mnc: '60400',
        mcc: 604,
        mnc: 0,
        operatorName: 'Maroc Telecom',
        mockLocationData: {
            latitude: 33.5731,
            longitude: -7.5898,
            city: 'Casablanca',
            accuracy: 10.0,
            altitude: 60.0,
            verticalAccuracy: 4.5,
            speed: 12.0,
            speedAccuracy: 2.8,
            meanSeaLevel: 55.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Uzbekistan': {
        locale: 'uz-UZ',
        country: 'UZ',
        langCode: 'uz',
        timezone: 'Asia/Tashkent',
        displayLang: 'Uzbek',
        mcc_mnc: '43405',
        mcc: 434,
        mnc: 5,
        operatorName: 'Ucell',
        mockLocationData: {
            latitude: 41.2995,
            longitude: 69.2401,
            city: 'Tashkent',
            accuracy: 12.0,
            altitude: 450.0,
            verticalAccuracy: 6.0,
            speed: 10.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 440.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Peru': {
        locale: 'es-PE',
        country: 'PE',
        langCode: 'es',
        timezone: 'America/Lima',
        displayLang: 'Spanish',
        mcc_mnc: '71606',
        mcc: 716,
        mnc: 6,
        operatorName: 'Claro Perú',
        mockLocationData: {
            latitude: -12.0464,
            longitude: -77.0428,
            city: 'Lima',
            accuracy: 10.0,
            altitude: 150.0,
            verticalAccuracy: 5.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 140.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Yemen': {
        locale: 'ar-YE',
        country: 'YE',
        langCode: 'ar',
        timezone: 'Asia/Aden',
        displayLang: 'Arabic',
        mcc_mnc: '42101',
        mcc: 421,
        mnc: 1,
        operatorName: 'SabaFon',
        mockLocationData: {
            latitude: 15.3547,
            longitude: 44.2066,
            city: 'Sana\'a',
            accuracy: 18.0,
            altitude: 2200.0,
            verticalAccuracy: 9.0,
            speed: 10.0,
            speedAccuracy: 4.0,
            meanSeaLevel: 2190.0,
            meanSeaLevelAccuracy: 5.5
        }
    },
    'Venezuela': {
        locale: 'es-VE',
        country: 'VE',
        langCode: 'es',
        timezone: 'America/Caracas',
        displayLang: 'Spanish',
        mcc_mnc: '73404',
        mcc: 734,
        mnc: 4,
        operatorName: 'Movilnet',
        mockLocationData: {
            latitude: 10.4806,
            longitude: -66.9036,
            city: 'Caracas',
            accuracy: 15.0,
            altitude: 900.0,
            verticalAccuracy: 7.0,
            speed: 12.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 890.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Nepal': {
        locale: 'ne-NP',
        country: 'NP',
        langCode: 'ne',
        timezone: 'Asia/Kathmandu',
        displayLang: 'Nepali',
        mcc_mnc: '42901',
        mcc: 429,
        mnc: 1,
        operatorName: 'Nepal Telecom',
        mockLocationData: {
            latitude: 27.7172,
            longitude: 85.3240,
            city: 'Kathmandu',
            accuracy: 20.0,
            altitude: 1400.0,
            verticalAccuracy: 10.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 1390.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'Australia': {
        locale: 'en-AU',
        country: 'AU',
        langCode: 'en',
        timezone: 'Australia/Sydney',
        displayLang: 'English',
        mcc_mnc: '50501',
        mcc: 505,
        mnc: 1,
        operatorName: 'Telstra',
        mockLocationData: {
            latitude: -33.8688,
            longitude: 151.2093,
            city: 'Sydney',
            accuracy: 5.0,
            altitude: 3.0,
            verticalAccuracy: 2.0,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 1.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Sri Lanka': {
        locale: 'si-LK',
        country: 'LK',
        langCode: 'si',
        timezone: 'Asia/Colombo',
        displayLang: 'Sinhala',
        mcc_mnc: '41301',
        mcc: 413,
        mnc: 1,
        operatorName: 'Dialog',
        mockLocationData: {
            latitude: 6.9271,
            longitude: 79.8612,
            city: 'Colombo',
            accuracy: 9.0,
            altitude: 1.0,
            verticalAccuracy: 3.5,
            speed: 7.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 0.5,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Chile': {
        locale: 'es-CL',
        country: 'CL',
        langCode: 'es',
        timezone: 'America/Santiago',
        displayLang: 'Spanish',
        mcc_mnc: '73001',
        mcc: 730,
        mnc: 1,
        operatorName: 'Entel',
        mockLocationData: {
            latitude: -33.4489,
            longitude: -70.6693,
            city: 'Santiago',
            accuracy: 8.0,
            altitude: 570.0,
            verticalAccuracy: 4.0,
            speed: 15.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 560.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Ecuador': {
        locale: 'es-EC',
        country: 'EC',
        langCode: 'es',
        timezone: 'America/Guayaquil',
        displayLang: 'Spanish',
        mcc_mnc: '74001',
        mcc: 740,
        mnc: 1,
        operatorName: 'Claro Ecuador',
        mockLocationData: {
            latitude: -2.2038,
            longitude: -79.8975,
            city: 'Guayaquil',
            accuracy: 10.0,
            altitude: 5.0,
            verticalAccuracy: 4.5,
            speed: 8.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 2.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Guatemala': {
        locale: 'es-GT',
        country: 'GT',
        langCode: 'es',
        timezone: 'America/Guatemala',
        displayLang: 'Spanish',
        mcc_mnc: '70401',
        mcc: 704,
        mnc: 1,
        operatorName: 'Tigo',
        mockLocationData: {
            latitude: 14.6349,
            longitude: -90.5069,
            city: 'Guatemala City',
            accuracy: 12.0,
            altitude: 1500.0,
            verticalAccuracy: 6.0,
            speed: 10.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 1490.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Romania': {
        locale: 'ro-RO',
        country: 'RO',
        langCode: 'ro',
        timezone: 'Europe/Bucharest',
        displayLang: 'Romanian',
        mcc_mnc: '22601',
        mcc: 226,
        mnc: 1,
        operatorName: 'Orange Romania',
        mockLocationData: {
            latitude: 44.4268,
            longitude: 26.1025,
            city: 'Bucharest',
            accuracy: 8.0,
            altitude: 70.0,
            verticalAccuracy: 3.5,
            speed: 15.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 65.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Netherlands': {
        locale: 'nl-NL',
        country: 'NL',
        langCode: 'nl',
        timezone: 'Europe/Amsterdam',
        displayLang: 'Dutch',
        mcc_mnc: '20408',
        mcc: 204,
        mnc: 8,
        operatorName: 'KPN',
        mockLocationData: {
            latitude: 52.3676,
            longitude: 4.9041,
            city: 'Amsterdam',
            accuracy: 4.0,
            altitude: -2.0,
            verticalAccuracy: 1.5,
            speed: 10.0,
            speedAccuracy: 1.8,
            meanSeaLevel: 0.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Zimbabwe': {
        locale: 'en-ZW',
        country: 'ZW',
        langCode: 'en',
        timezone: 'Africa/Harare',
        displayLang: 'English',
        mcc_mnc: '64804',
        mcc: 648,
        mnc: 4,
        operatorName: 'Econet',
        mockLocationData: {
            latitude: -17.8252,
            longitude: 31.0335,
            city: 'Harare',
            accuracy: 15.0,
            altitude: 1483.0,
            verticalAccuracy: 7.0,
            speed: 10.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 1475.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Cambodia': {
        locale: 'km-KH',
        country: 'KH',
        langCode: 'km',
        timezone: 'Asia/Phnom_Penh',
        displayLang: 'Khmer',
        mcc_mnc: '45601',
        mcc: 456,
        mnc: 1,
        operatorName: 'Cellcard',
        mockLocationData: {
            latitude: 11.5564,
            longitude: 104.9282,
            city: 'Phnom Penh',
            accuracy: 10.0,
            altitude: 12.0,
            verticalAccuracy: 4.0,
            speed: 8.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 8.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Belgium': {
        locale: 'nl-BE',
        country: 'BE',
        langCode: 'nl',
        timezone: 'Europe/Brussels',
        displayLang: 'Dutch',
        mcc_mnc: '20601',
        mcc: 206,
        mnc: 1,
        operatorName: 'Proximus',
        mockLocationData: {
            latitude: 50.8503,
            longitude: 4.3517,
            city: 'Brussels',
            accuracy: 5.0,
            altitude: 50.0,
            verticalAccuracy: 2.5,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 45.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Haiti': {
        locale: 'fr-HT',
        country: 'HT',
        langCode: 'fr',
        timezone: 'America/Port-au-Prince',
        displayLang: 'French',
        mcc_mnc: '37201',
        mcc: 372,
        mnc: 1,
        operatorName: 'Digicel Haiti',
        mockLocationData: {
            latitude: 18.5392,
            longitude: -72.3364,
            city: 'Port-au-Prince',
            accuracy: 15.0,
            altitude: 35.0,
            verticalAccuracy: 7.0,
            speed: 5.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 30.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Jordan': {
        locale: 'ar-JO',
        country: 'JO',
        langCode: 'ar',
        timezone: 'Asia/Amman',
        displayLang: 'Arabic',
        mcc_mnc: '41601',
        mcc: 416,
        mnc: 1,
        operatorName: 'Zain Jordan',
        mockLocationData: {
            latitude: 31.9454,
            longitude: 35.9284,
            city: 'Amman',
            accuracy: 10.0,
            altitude: 800.0,
            verticalAccuracy: 5.0,
            speed: 15.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 790.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Sweden': {
        locale: 'sv-SE',
        country: 'SE',
        langCode: 'sv',
        timezone: 'Europe/Stockholm',
        displayLang: 'Swedish',
        mcc_mnc: '24001',
        mcc: 240,
        mnc: 1,
        operatorName: 'Telia',
        mockLocationData: {
            latitude: 59.3293,
            longitude: 18.0686,
            city: 'Stockholm',
            accuracy: 6.0,
            altitude: 16.0,
            verticalAccuracy: 2.5,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 10.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Greece': {
        locale: 'el-GR',
        country: 'GR',
        langCode: 'el',
        timezone: 'Europe/Athens',
        displayLang: 'Greek',
        mcc_mnc: '20201',
        mcc: 202,
        mnc: 1,
        operatorName: 'Cosmote',
        mockLocationData: {
            latitude: 37.9838,
            longitude: 23.7275,
            city: 'Athens',
            accuracy: 7.0,
            altitude: 70.0,
            verticalAccuracy: 3.0,
            speed: 10.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 65.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Portugal': {
        locale: 'pt-PT',
        country: 'PT',
        langCode: 'pt',
        timezone: 'Europe/Lisbon',
        displayLang: 'Portuguese',
        mcc_mnc: '26801',
        mcc: 268,
        mnc: 1,
        operatorName: 'MEO',
        mockLocationData: {
            latitude: 38.7223,
            longitude: -9.1393,
            city: 'Lisbon',
            accuracy: 6.0,
            altitude: 100.0,
            verticalAccuracy: 2.8,
            speed: 15.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 95.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Hungary': {
        locale: 'hu-HU',
        country: 'HU',
        langCode: 'hu',
        timezone: 'Europe/Budapest',
        displayLang: 'Hungarian',
        mcc_mnc: '21630',
        mcc: 216,
        mnc: 30,
        operatorName: 'Magyar Telekom',
        mockLocationData: {
            latitude: 47.4979,
            longitude: 19.0402,
            city: 'Budapest',
            accuracy: 7.0,
            altitude: 100.0,
            verticalAccuracy: 3.5,
            speed: 12.0,
            speedAccuracy: 2.2,
            meanSeaLevel: 95.0,
            meanSeaLevelAccuracy: 3.0
        }
    },
    'Honduras': {
        locale: 'es-HN',
        country: 'HN',
        langCode: 'es',
        timezone: 'America/Tegucigalpa',
        displayLang: 'Spanish',
        mcc_mnc: '70801',
        mcc: 708,
        mnc: 1,
        operatorName: 'Tigo Honduras',
        mockLocationData: {
            latitude: 14.0818,
            longitude: -87.2068,
            city: 'Tegucigalpa',
            accuracy: 13.0,
            altitude: 990.0,
            verticalAccuracy: 6.0,
            speed: 9.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 980.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Belarus': {
        locale: 'be-BY',
        country: 'BY',
        langCode: 'be',
        timezone: 'Europe/Minsk',
        displayLang: 'Belarusian',
        mcc_mnc: '25701',
        mcc: 257,
        mnc: 1,
        operatorName: 'MTS Belarus',
        mockLocationData: {
            latitude: 53.9045,
            longitude: 27.5615,
            city: 'Minsk',
            accuracy: 10.0,
            altitude: 220.0,
            verticalAccuracy: 5.0,
            speed: 15.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 215.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Israel': {
        locale: 'he-IL',
        country: 'IL',
        langCode: 'he',
        timezone: 'Asia/Jerusalem',
        displayLang: 'Hebrew',
        mcc_mnc: '42502',
        mcc: 425,
        mnc: 2,
        operatorName: 'Partner',
        mockLocationData: {
            latitude: 32.0853,
            longitude: 34.7818,
            city: 'Tel Aviv',
            accuracy: 5.0,
            altitude: 10.0,
            verticalAccuracy: 2.5,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Syria': {
        locale: 'ar-SY',
        country: 'SY',
        langCode: 'ar',
        timezone: 'Asia/Damascus',
        displayLang: 'Arabic',
        mcc_mnc: '41701',
        mcc: 417,
        mnc: 1,
        operatorName: 'Syriatel',
        mockLocationData: {
            latitude: 33.5130,
            longitude: 36.2919,
            city: 'Damascus',
            accuracy: 15.0,
            altitude: 690.0,
            verticalAccuracy: 7.0,
            speed: 8.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 680.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Taiwan': {
        locale: 'zh-TW',
        country: 'TW',
        langCode: 'zh',
        timezone: 'Asia/Taipei',
        displayLang: 'Chinese',
        mcc_mnc: '46692',
        mcc: 466,
        mnc: 92,
        operatorName: 'Chunghwa Telecom',
        mockLocationData: {
            latitude: 25.0330,
            longitude: 121.5654,
            city: 'Taipei',
            accuracy: 6.0,
            altitude: 8.0,
            verticalAccuracy: 2.5,
            speed: 10.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Malawi': {
        locale: 'en-MW',
        country: 'MW',
        langCode: 'en',
        timezone: 'Africa/Blantyre',
        displayLang: 'English',
        mcc_mnc: '65001',
        mcc: 650,
        mnc: 1,
        operatorName: 'TNM',
        mockLocationData: {
            latitude: -13.9632,
            longitude: 33.7841,
            city: 'Lilongwe',
            accuracy: 20.0,
            altitude: 1050.0,
            verticalAccuracy: 10.0,
            speed: 7.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 1040.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'Zambia': {
        locale: 'en-ZM',
        country: 'ZM',
        langCode: 'en',
        timezone: 'Africa/Lusaka',
        displayLang: 'English',
        mcc_mnc: '64501',
        mcc: 645,
        mnc: 1,
        operatorName: 'MTN Zambia',
        mockLocationData: {
            latitude: -15.4167,
            longitude: 28.2833,
            city: 'Lusaka',
            accuracy: 15.0,
            altitude: 1280.0,
            verticalAccuracy: 7.0,
            speed: 10.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 1270.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Chad': {
        locale: 'fr-TD',
        country: 'TD',
        langCode: 'fr',
        timezone: 'Africa/Ndjamena',
        displayLang: 'French',
        mcc_mnc: '62201',
        mcc: 622,
        mnc: 1,
        operatorName: 'Tigo Chad',
        mockLocationData: {
            latitude: 12.1068,
            longitude: 15.0456,
            city: 'N\'Djamena',
            accuracy: 18.0,
            altitude: 295.0,
            verticalAccuracy: 8.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 290.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Senegal': {
        locale: 'fr-SN',
        country: 'SN',
        langCode: 'fr',
        timezone: 'Africa/Dakar',
        displayLang: 'French',
        mcc_mnc: '60801',
        mcc: 608,
        mnc: 1,
        operatorName: 'Orange Sonatel',
        mockLocationData: {
            latitude: 14.6934,
            longitude: -17.4446,
            city: 'Dakar',
            accuracy: 10.0,
            altitude: 22.0,
            verticalAccuracy: 4.5,
            speed: 10.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 15.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Benin': {
        locale: 'fr-BJ',
        country: 'BJ',
        langCode: 'fr',
        timezone: 'Africa/Porto-Novo',
        displayLang: 'French',
        mcc_mnc: '61604',
        mcc: 616,
        mnc: 4,
        operatorName: 'Moov Africa',
        mockLocationData: {
            latitude: 6.3654,
            longitude: 2.4206,
            city: 'Porto-Novo',
            accuracy: 12.0,
            altitude: 38.0,
            verticalAccuracy: 5.0,
            speed: 7.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 30.0,
            meanSeaLevelAccuracy: 3.0
        }
    },
    'Guinea': {
        locale: 'fr-GN',
        country: 'GN',
        langCode: 'fr',
        timezone: 'Africa/Conakry',
        displayLang: 'French',
        mcc_mnc: '61101',
        mcc: 611,
        mnc: 1,
        operatorName: 'Orange Guinea',
        mockLocationData: {
            latitude: 9.5099,
            longitude: -13.7122,
            city: 'Conakry',
            accuracy: 15.0,
            altitude: 5.0,
            verticalAccuracy: 7.0,
            speed: 6.0,
            speedAccuracy: 1.8,
            meanSeaLevel: 2.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Rwanda': {
        locale: 'en-RW',
        country: 'RW',
        langCode: 'en',
        timezone: 'Africa/Kigali',
        displayLang: 'English',
        mcc_mnc: '63510',
        mcc: 635,
        mnc: 10,
        operatorName: 'MTN Rwanda',
        mockLocationData: {
            latitude: -1.9403,
            longitude: 29.8739,
            city: 'Kigali',
            accuracy: 12.0,
            altitude: 1567.0,
            verticalAccuracy: 6.0,
            speed: 10.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 1560.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Burundi': {
        locale: 'fr-BI',
        country: 'BI',
        langCode: 'fr',
        timezone: 'Africa/Bujumbura',
        displayLang: 'French',
        mcc_mnc: '64201',
        mcc: 642,
        mnc: 1,
        operatorName: 'Onatel',
        mockLocationData: {
            latitude: -3.3756,
            longitude: 29.3611,
            city: 'Bujumbura',
            accuracy: 18.0,
            altitude: 780.0,
            verticalAccuracy: 8.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 770.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Somalia': {
        locale: 'so-SO',
        country: 'SO',
        langCode: 'so',
        timezone: 'Africa/Mogadishu',
        displayLang: 'Somali',
        mcc_mnc: '63730',
        mcc: 637,
        mnc: 30,
        operatorName: 'Hormuud Telecom',
        mockLocationData: {
            latitude: 2.0371,
            longitude: 45.3438,
            city: 'Mogadishu',
            accuracy: 20.0,
            altitude: 9.0,
            verticalAccuracy: 9.0,
            speed: 5.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Bolivia': {
        locale: 'es-BO',
        country: 'BO',
        langCode: 'es',
        timezone: 'America/La_Paz',
        displayLang: 'Spanish',
        mcc_mnc: '73602',
        mcc: 736,
        mnc: 2,
        operatorName: 'Entel',
        mockLocationData: {
            latitude: -16.5000,
            longitude: -68.1500,
            city: 'La Paz',
            accuracy: 15.0,
            altitude: 3640.0,
            verticalAccuracy: 7.0,
            speed: 10.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 3630.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'Tunisia': {
        locale: 'ar-TN',
        country: 'TN',
        langCode: 'ar',
        timezone: 'Africa/Tunis',
        displayLang: 'Arabic',
        mcc_mnc: '60502',
        mcc: 605,
        mnc: 2,
        operatorName: 'Ooredoo Tunisia',
        mockLocationData: {
            latitude: 36.8065,
            longitude: 10.1815,
            city: 'Tunis',
            accuracy: 9.0,
            altitude: 4.0,
            verticalAccuracy: 4.0,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 2.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Czechia': {
        locale: 'cs-CZ',
        country: 'CZ',
        langCode: 'cs',
        timezone: 'Europe/Prague',
        displayLang: 'Czech',
        mcc_mnc: '23003',
        mcc: 230,
        mnc: 3,
        operatorName: 'Vodafone Czech Republic',
        mockLocationData: {
            latitude: 50.0755,
            longitude: 14.4378,
            city: 'Prague',
            accuracy: 7.0,
            altitude: 235.0,
            verticalAccuracy: 3.0,
            speed: 15.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 230.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Dominican Republic': {
        locale: 'es-DO',
        country: 'DO',
        langCode: 'es',
        timezone: 'America/Santo_Domingo',
        displayLang: 'Spanish',
        mcc_mnc: '37001',
        mcc: 370,
        mnc: 1,
        operatorName: 'Claro Dominicana',
        mockLocationData: {
            latitude: 18.4861,
            longitude: -69.9312,
            city: 'Santo Domingo',
            accuracy: 10.0,
            altitude: 14.0,
            verticalAccuracy: 4.5,
            speed: 10.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 10.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Azerbaijan': {
        locale: 'az-AZ',
        country: 'AZ',
        langCode: 'az',
        timezone: 'Asia/Baku',
        displayLang: 'Azerbaijani',
        mcc_mnc: '40001',
        mcc: 400,
        mnc: 1,
        operatorName: 'Azercell',
        mockLocationData: {
            latitude: 40.4093,
            longitude: 49.8671,
            city: 'Baku',
            accuracy: 8.0,
            altitude: 10.0,
            verticalAccuracy: 3.5,
            speed: 15.0,
            speedAccuracy: 2.8,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Singapore': {
        locale: 'en-SG',
        country: 'SG',
        langCode: 'en',
        timezone: 'Asia/Singapore',
        displayLang: 'English',
        mcc_mnc: '52501',
        mcc: 525,
        mnc: 1,
        operatorName: 'Singtel',
        mockLocationData: {
            latitude: 1.3521,
            longitude: 103.8198,
            city: 'Singapore',
            accuracy: 3.0,
            altitude: 15.0,
            verticalAccuracy: 1.2,
            speed: 8.0,
            speedAccuracy: 1.0,
            meanSeaLevel: 10.0,
            meanSeaLevelAccuracy: 0.8
        }
    },
    'Denmark': {
        locale: 'da-DK',
        country: 'DK',
        langCode: 'da',
        timezone: 'Europe/Copenhagen',
        displayLang: 'Danish',
        mcc_mnc: '23801',
        mcc: 238,
        mnc: 1,
        operatorName: 'TDC',
        mockLocationData: {
            latitude: 55.6761,
            longitude: 12.5683,
            city: 'Copenhagen',
            accuracy: 5.0,
            altitude: 10.0,
            verticalAccuracy: 2.0,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Tunisia': {
        locale: 'fr-TN',
        country: 'TN',
        langCode: 'fr',
        timezone: 'Africa/Tunis',
        displayLang: 'French',
        mcc_mnc: '60502',
        mcc: 605,
        mnc: 2,
        operatorName: 'Ooredoo Tunisia',
        mockLocationData: {
            latitude: 36.8065,
            longitude: 10.1815,
            city: 'Tunis',
            accuracy: 9.0,
            altitude: 4.0,
            verticalAccuracy: 4.0,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 2.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Finland': {
        locale: 'fi-FI',
        country: 'FI',
        langCode: 'fi',
        timezone: 'Europe/Helsinki',
        displayLang: 'Finnish',
        mcc_mnc: '24405',
        mcc: 244,
        mnc: 5,
        operatorName: 'Elisa',
        mockLocationData: {
            latitude: 60.1695,
            longitude: 24.9354,
            city: 'Helsinki',
            accuracy: 7.0,
            altitude: 20.0,
            verticalAccuracy: 3.0,
            speed: 15.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 15.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'New Zealand': {
        locale: 'en-NZ',
        country: 'NZ',
        langCode: 'en',
        timezone: 'Pacific/Auckland',
        displayLang: 'English',
        mcc_mnc: '53005',
        mcc: 530,
        mnc: 5,
        operatorName: 'Vodafone NZ',
        mockLocationData: {
            latitude: -36.8485,
            longitude: 174.7633,
            city: 'Auckland',
            accuracy: 6.0,
            altitude: 10.0,
            verticalAccuracy: 2.5,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Kuwait': {
        locale: 'ar-KW',
        country: 'KW',
        langCode: 'ar',
        timezone: 'Asia/Kuwait',
        displayLang: 'Arabic',
        mcc_mnc: '41902',
        mcc: 419,
        mnc: 2,
        operatorName: 'Zain Kuwait',
        mockLocationData: {
            latitude: 29.3759,
            longitude: 47.9774,
            city: 'Kuwait City',
            accuracy: 8.0,
            altitude: 2.0,
            verticalAccuracy: 3.5,
            speed: 18.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 1.0,
            meanSeaLevelAccuracy: 1.2
        }
    },
    'Costa Rica': {
        locale: 'es-CR',
        country: 'CR',
        langCode: 'es',
        timezone: 'America/Costa_Rica',
        displayLang: 'Spanish',
        mcc_mnc: '71201',
        mcc: 712,
        mnc: 1,
        operatorName: 'ICE',
        mockLocationData: {
            latitude: 9.9281,
            longitude: -84.0907,
            city: 'San José',
            accuracy: 10.0,
            altitude: 1172.0,
            verticalAccuracy: 5.0,
            speed: 10.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 1165.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Norway': {
        locale: 'nb-NO',
        country: 'NO',
        langCode: 'nb',
        timezone: 'Europe/Oslo',
        displayLang: 'Norwegian',
        mcc_mnc: '24201',
        mcc: 242,
        mnc: 1,
        operatorName: 'Telenor',
        mockLocationData: {
            latitude: 59.9139,
            longitude: 10.7522,
            city: 'Oslo',
            accuracy: 6.0,
            altitude: 23.0,
            verticalAccuracy: 2.5,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 18.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Ireland': {
        locale: 'en-IE',
        country: 'IE',
        langCode: 'en',
        timezone: 'Europe/Dublin',
        displayLang: 'English',
        mcc_mnc: '27203',
        mcc: 272,
        mnc: 3,
        operatorName: 'Vodafone Ireland',
        mockLocationData: {
            latitude: 53.3498,
            longitude: -6.2603,
            city: 'Dublin',
            accuracy: 5.0,
            altitude: 20.0,
            verticalAccuracy: 2.0,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 15.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Hong Kong': {
        locale: 'en-HK',
        country: 'HK',
        langCode: 'en',
        timezone: 'Asia/Hong_Kong',
        displayLang: 'English',
        mcc_mnc: '45412',
        mcc: 454,
        mnc: 12,
        operatorName: 'SmarTone',
        mockLocationData: {
            latitude: 22.3193,
            longitude: 114.1694,
            city: 'Hong Kong',
            accuracy: 4.0,
            altitude: 35.0,
            verticalAccuracy: 1.5,
            speed: 15.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 30.0,
            meanSeaLevelAccuracy: 1.2
        }
    },
    'Switzerland': {
        locale: 'de-CH',
        country: 'CH',
        langCode: 'de',
        timezone: 'Europe/Zurich',
        displayLang: 'German',
        mcc_mnc: '22801',
        mcc: 228,
        mnc: 1,
        operatorName: 'Swisscom',
        mockLocationData: {
            latitude: 47.3769,
            longitude: 8.5417,
            city: 'Zurich',
            accuracy: 5.0,
            altitude: 408.0,
            verticalAccuracy: 2.0,
            speed: 12.0,
            speedAccuracy: 1.8,
            meanSeaLevel: 400.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Belgium': {
        locale: 'fr-BE',
        country: 'BE',
        langCode: 'fr',
        timezone: 'Europe/Brussels',
        displayLang: 'French',
        mcc_mnc: '20601',
        mcc: 206,
        mnc: 1,
        operatorName: 'Proximus',
        mockLocationData: {
            latitude: 50.8503,
            longitude: 4.3517,
            city: 'Brussels',
            accuracy: 5.0,
            altitude: 50.0,
            verticalAccuracy: 2.5,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 45.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Sweden': {
        locale: 'en-SE',
        country: 'SE',
        langCode: 'en',
        timezone: 'Europe/Stockholm',
        displayLang: 'English',
        mcc_mnc: '24001',
        mcc: 240,
        mnc: 1,
        operatorName: 'Telia',
        mockLocationData: {
            latitude: 59.3293,
            longitude: 18.0686,
            city: 'Stockholm',
            accuracy: 6.0,
            altitude: 16.0,
            verticalAccuracy: 2.5,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 10.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Greece': {
        locale: 'en-GR',
        country: 'GR',
        langCode: 'en',
        timezone: 'Europe/Athens',
        displayLang: 'English',
        mcc_mnc: '20201',
        mcc: 202,
        mnc: 1,
        operatorName: 'Cosmote',
        mockLocationData: {
            latitude: 37.9838,
            longitude: 23.7275,
            city: 'Athens',
            accuracy: 7.0,
            altitude: 70.0,
            verticalAccuracy: 3.0,
            speed: 10.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 65.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Portugal': {
        locale: 'en-PT',
        country: 'PT',
        langCode: 'en',
        timezone: 'Europe/Lisbon',
        displayLang: 'English',
        mcc_mnc: '26801',
        mcc: 268,
        mnc: 1,
        operatorName: 'MEO',
        mockLocationData: {
            latitude: 38.7223,
            longitude: -9.1393,
            city: 'Lisbon',
            accuracy: 6.0,
            altitude: 100.0,
            verticalAccuracy: 2.8,
            speed: 15.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 95.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Hungary': {
        locale: 'en-HU',
        country: 'HU',
        langCode: 'en',
        timezone: 'Europe/Budapest',
        displayLang: 'English',
        mcc_mnc: '21630',
        mcc: 216,
        mnc: 30,
        operatorName: 'Magyar Telekom',
        mockLocationData: {
            latitude: 47.4979,
            longitude: 19.0402,
            city: 'Budapest',
            accuracy: 7.0,
            altitude: 100.0,
            verticalAccuracy: 3.5,
            speed: 12.0,
            speedAccuracy: 2.2,
            meanSeaLevel: 95.0,
            meanSeaLevelAccuracy: 3.0
        }
    },
    'Honduras': {
        locale: 'en-HN',
        country: 'HN',
        langCode: 'en',
        timezone: 'America/Tegucigalpa',
        displayLang: 'English',
        mcc_mnc: '70801',
        mcc: 708,
        mnc: 1,
        operatorName: 'Tigo Honduras',
        mockLocationData: {
            latitude: 14.0818,
            longitude: -87.2068,
            city: 'Tegucigalpa',
            accuracy: 13.0,
            altitude: 990.0,
            verticalAccuracy: 6.0,
            speed: 9.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 980.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Belarus': {
        locale: 'en-BY',
        country: 'BY',
        langCode: 'en',
        timezone: 'Europe/Minsk',
        displayLang: 'English',
        mcc_mnc: '25701',
        mcc: 257,
        mnc: 1,
        operatorName: 'MTS Belarus',
        mockLocationData: {
            latitude: 53.9045,
            longitude: 27.5615,
            city: 'Minsk',
            accuracy: 10.0,
            altitude: 220.0,
            verticalAccuracy: 5.0,
            speed: 15.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 215.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Israel': {
        locale: 'en-IL',
        country: 'IL',
        langCode: 'en',
        timezone: 'Asia/Jerusalem',
        displayLang: 'English',
        mcc_mnc: '42502',
        mcc: 425,
        mnc: 2,
        operatorName: 'Partner',
        mockLocationData: {
            latitude: 32.0853,
            longitude: 34.7818,
            city: 'Tel Aviv',
            accuracy: 5.0,
            altitude: 10.0,
            verticalAccuracy: 2.5,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Syria': {
        locale: 'en-SY',
        country: 'SY',
        langCode: 'en',
        timezone: 'Asia/Damascus',
        displayLang: 'English',
        mcc_mnc: '41701',
        mcc: 417,
        mnc: 1,
        operatorName: 'Syriatel',
        mockLocationData: {
            latitude: 33.5130,
            longitude: 36.2919,
            city: 'Damascus',
            accuracy: 15.0,
            altitude: 690.0,
            verticalAccuracy: 7.0,
            speed: 8.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 680.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Taiwan': {
        locale: 'en-TW',
        country: 'TW',
        langCode: 'en',
        timezone: 'Asia/Taipei',
        displayLang: 'English',
        mcc_mnc: '46692',
        mcc: 466,
        mnc: 92,
        operatorName: 'Chunghwa Telecom',
        mockLocationData: {
            latitude: 25.0330,
            longitude: 121.5654,
            city: 'Taipei',
            accuracy: 6.0,
            altitude: 8.0,
            verticalAccuracy: 2.5,
            speed: 10.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Malawi': {
        locale: 'ny-MW',
        country: 'MW',
        langCode: 'ny',
        timezone: 'Africa/Blantyre',
        displayLang: 'Chichewa',
        mcc_mnc: '65001',
        mcc: 650,
        mnc: 1,
        operatorName: 'TNM',
        mockLocationData: {
            latitude: -13.9632,
            longitude: 33.7841,
            city: 'Lilongwe',
            accuracy: 20.0,
            altitude: 1050.0,
            verticalAccuracy: 10.0,
            speed: 7.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 1040.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'Zambia': {
        locale: 'en-ZM',
        country: 'ZM',
        langCode: 'en',
        timezone: 'Africa/Lusaka',
        displayLang: 'English',
        mcc_mnc: '64501',
        mcc: 645,
        mnc: 1,
        operatorName: 'MTN Zambia',
        mockLocationData: {
            latitude: -15.4167,
            longitude: 28.2833,
            city: 'Lusaka',
            accuracy: 15.0,
            altitude: 1280.0,
            verticalAccuracy: 7.0,
            speed: 10.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 1270.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Chad': {
        locale: 'ar-TD',
        country: 'TD',
        langCode: 'ar',
        timezone: 'Africa/Ndjamena',
        displayLang: 'Arabic',
        mcc_mnc: '62201',
        mcc: 622,
        mnc: 1,
        operatorName: 'Tigo Chad',
        mockLocationData: {
            latitude: 12.1068,
            longitude: 15.0456,
            city: 'N\'Djamena',
            accuracy: 18.0,
            altitude: 295.0,
            verticalAccuracy: 8.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 290.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Senegal': {
        locale: 'wo-SN',
        country: 'SN',
        langCode: 'wo',
        timezone: 'Africa/Dakar',
        displayLang: 'Wolof',
        mcc_mnc: '60801',
        mcc: 608,
        mnc: 1,
        operatorName: 'Orange Sonatel',
        mockLocationData: {
            latitude: 14.6934,
            longitude: -17.4446,
            city: 'Dakar',
            accuracy: 10.0,
            altitude: 22.0,
            verticalAccuracy: 4.5,
            speed: 10.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 15.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Benin': {
        locale: 'fr-BJ',
        country: 'BJ',
        langCode: 'fr',
        timezone: 'Africa/Porto-Novo',
        displayLang: 'French',
        mcc_mnc: '61604',
        mcc: 616,
        mnc: 4,
        operatorName: 'Moov Africa',
        mockLocationData: {
            latitude: 6.3654,
            longitude: 2.4206,
            city: 'Porto-Novo',
            accuracy: 12.0,
            altitude: 38.0,
            verticalAccuracy: 5.0,
            speed: 7.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 30.0,
            meanSeaLevelAccuracy: 3.0
        }
    },
    'Guinea': {
        locale: 'fr-GN',
        country: 'GN',
        langCode: 'fr',
        timezone: 'Africa/Conakry',
        displayLang: 'French',
        mcc_mnc: '61101',
        mcc: 611,
        mnc: 1,
        operatorName: 'Orange Guinea',
        mockLocationData: {
            latitude: 9.5099,
            longitude: -13.7122,
            city: 'Conakry',
            accuracy: 15.0,
            altitude: 5.0,
            verticalAccuracy: 7.0,
            speed: 6.0,
            speedAccuracy: 1.8,
            meanSeaLevel: 2.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Rwanda': {
        locale: 'en-RW',
        country: 'RW',
        langCode: 'en',
        timezone: 'Africa/Kigali',
        displayLang: 'English',
        mcc_mnc: '63510',
        mcc: 635,
        mnc: 10,
        operatorName: 'MTN Rwanda',
        mockLocationData: {
            latitude: -1.9403,
            longitude: 29.8739,
            city: 'Kigali',
            accuracy: 12.0,
            altitude: 1567.0,
            verticalAccuracy: 6.0,
            speed: 10.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 1560.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Burundi': {
        locale: 'fr-BI',
        country: 'BI',
        langCode: 'fr',
        timezone: 'Africa/Bujumbura',
        displayLang: 'French',
        mcc_mnc: '64201',
        mcc: 642,
        mnc: 1,
        operatorName: 'Onatel',
        mockLocationData: {
            latitude: -3.3756,
            longitude: 29.3611,
            city: 'Bujumbura',
            accuracy: 18.0,
            altitude: 780.0,
            verticalAccuracy: 8.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 770.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Somalia': {
        locale: 'so-SO',
        country: 'SO',
        langCode: 'so',
        timezone: 'Africa/Mogadishu',
        displayLang: 'Somali',
        mcc_mnc: '63730',
        mcc: 637,
        mnc: 30,
        operatorName: 'Hormuud Telecom',
        mockLocationData: {
            latitude: 2.0371,
            longitude: 45.3438,
            city: 'Mogadishu',
            accuracy: 20.0,
            altitude: 9.0,
            verticalAccuracy: 9.0,
            speed: 5.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Bolivia': {
        locale: 'es-BO',
        country: 'BO',
        langCode: 'es',
        timezone: 'America/La_Paz',
        displayLang: 'Spanish',
        mcc_mnc: '73602',
        mcc: 736,
        mnc: 2,
        operatorName: 'Entel',
        mockLocationData: {
            latitude: -16.5000,
            longitude: -68.1500,
            city: 'La Paz',
            accuracy: 15.0,
            altitude: 3640.0,
            verticalAccuracy: 7.0,
            speed: 10.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 3630.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'Tunisia': {
        locale: 'ar-TN',
        country: 'TN',
        langCode: 'ar',
        timezone: 'Africa/Tunis',
        displayLang: 'Arabic',
        mcc_mnc: '60502',
        mcc: 605,
        mnc: 2,
        operatorName: 'Ooredoo Tunisia',
        mockLocationData: {
            latitude: 36.8065,
            longitude: 10.1815,
            city: 'Tunis',
            accuracy: 9.0,
            altitude: 4.0,
            verticalAccuracy: 4.0,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 2.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Czechia': {
        locale: 'cs-CZ',
        country: 'CZ',
        langCode: 'cs',
        timezone: 'Europe/Prague',
        displayLang: 'Czech',
        mcc_mnc: '23003',
        mcc: 230,
        mnc: 3,
        operatorName: 'Vodafone Czech Republic',
        mockLocationData: {
            latitude: 50.0755,
            longitude: 14.4378,
            city: 'Prague',
            accuracy: 7.0,
            altitude: 235.0,
            verticalAccuracy: 3.0,
            speed: 15.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 230.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Dominican Republic': {
        locale: 'es-DO',
        country: 'DO',
        langCode: 'es',
        timezone: 'America/Santo_Domingo',
        displayLang: 'Spanish',
        mcc_mnc: '37001',
        mcc: 370,
        mnc: 1,
        operatorName: 'Claro Dominicana',
        mockLocationData: {
            latitude: 18.4861,
            longitude: -69.9312,
            city: 'Santo Domingo',
            accuracy: 10.0,
            altitude: 14.0,
            verticalAccuracy: 4.5,
            speed: 10.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 10.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Azerbaijan': {
        locale: 'az-AZ',
        country: 'AZ',
        langCode: 'az',
        timezone: 'Asia/Baku',
        displayLang: 'Azerbaijani',
        mcc_mnc: '40001',
        mcc: 400,
        mnc: 1,
        operatorName: 'Azercell',
        mockLocationData: {
            latitude: 40.4093,
            longitude: 49.8671,
            city: 'Baku',
            accuracy: 8.0,
            altitude: 10.0,
            verticalAccuracy: 3.5,
            speed: 15.0,
            speedAccuracy: 2.8,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Singapore': {
        locale: 'en-SG',
        country: 'SG',
        langCode: 'en',
        timezone: 'Asia/Singapore',
        displayLang: 'English',
        mcc_mnc: '52501',
        mcc: 525,
        mnc: 1,
        operatorName: 'Singtel',
        mockLocationData: {
            latitude: 1.3521,
            longitude: 103.8198,
            city: 'Singapore',
            accuracy: 3.0,
            altitude: 15.0,
            verticalAccuracy: 1.2,
            speed: 8.0,
            speedAccuracy: 1.0,
            meanSeaLevel: 10.0,
            meanSeaLevelAccuracy: 0.8
        }
    },
    'Denmark': {
        locale: 'da-DK',
        country: 'DK',
        langCode: 'da',
        timezone: 'Europe/Copenhagen',
        displayLang: 'Danish',
        mcc_mnc: '23801',
        mcc: 238,
        mnc: 1,
        operatorName: 'TDC',
        mockLocationData: {
            latitude: 55.6761,
            longitude: 12.5683,
            city: 'Copenhagen',
            accuracy: 5.0,
            altitude: 10.0,
            verticalAccuracy: 2.0,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Finland': {
        locale: 'fi-FI',
        country: 'FI',
        langCode: 'fi',
        timezone: 'Europe/Helsinki',
        displayLang: 'Finnish',
        mcc_mnc: '24405',
        mcc: 244,
        mnc: 5,
        operatorName: 'Elisa',
        mockLocationData: {
            latitude: 60.1695,
            longitude: 24.9354,
            city: 'Helsinki',
            accuracy: 7.0,
            altitude: 20.0,
            verticalAccuracy: 3.0,
            speed: 15.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 15.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'New Zealand': {
        locale: 'en-NZ',
        country: 'NZ',
        langCode: 'en',
        timezone: 'Pacific/Auckland',
        displayLang: 'English',
        mcc_mnc: '53005',
        mcc: 530,
        mnc: 5,
        operatorName: 'Vodafone NZ',
        mockLocationData: {
            latitude: -36.8485,
            longitude: 174.7633,
            city: 'Auckland',
            accuracy: 6.0,
            altitude: 10.0,
            verticalAccuracy: 2.5,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Kuwait': {
        locale: 'ar-KW',
        country: 'KW',
        langCode: 'ar',
        timezone: 'Asia/Kuwait',
        displayLang: 'Arabic',
        mcc_mnc: '41902',
        mcc: 419,
        mnc: 2,
        operatorName: 'Zain Kuwait',
        mockLocationData: {
            latitude: 29.3759,
            longitude: 47.9774,
            city: 'Kuwait City',
            accuracy: 8.0,
            altitude: 2.0,
            verticalAccuracy: 3.5,
            speed: 18.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 1.0,
            meanSeaLevelAccuracy: 1.2
        }
    },
    'Costa Rica': {
        locale: 'es-CR',
        country: 'CR',
        langCode: 'es',
        timezone: 'America/Costa_Rica',
        displayLang: 'Spanish',
        mcc_mnc: '71201',
        mcc: 712,
        mnc: 1,
        operatorName: 'ICE',
        mockLocationData: {
            latitude: 9.9281,
            longitude: -84.0907,
            city: 'San José',
            accuracy: 10.0,
            altitude: 1172.0,
            verticalAccuracy: 5.0,
            speed: 10.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 1165.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Norway': {
        locale: 'nb-NO',
        country: 'NO',
        langCode: 'nb',
        timezone: 'Europe/Oslo',
        displayLang: 'Norwegian',
        mcc_mnc: '24201',
        mcc: 242,
        mnc: 1,
        operatorName: 'Telenor',
        mockLocationData: {
            latitude: 59.9139,
            longitude: 10.7522,
            city: 'Oslo',
            accuracy: 6.0,
            altitude: 23.0,
            verticalAccuracy: 2.5,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 18.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Ireland': {
        locale: 'en-IE',
        country: 'IE',
        langCode: 'en',
        timezone: 'Europe/Dublin',
        displayLang: 'English',
        mcc_mnc: '27203',
        mcc: 272,
        mnc: 3,
        operatorName: 'Vodafone Ireland',
        mockLocationData: {
            latitude: 53.3498,
            longitude: -6.2603,
            city: 'Dublin',
            accuracy: 5.0,
            altitude: 20.0,
            verticalAccuracy: 2.0,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 15.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Hong Kong': {
        locale: 'en-HK',
        country: 'HK',
        langCode: 'en',
        timezone: 'Asia/Hong_Kong',
        displayLang: 'English',
        mcc_mnc: '45412',
        mcc: 454,
        mnc: 12,
        operatorName: 'SmarTone',
        mockLocationData: {
            latitude: 22.3193,
            longitude: 114.1694,
            city: 'Hong Kong',
            accuracy: 4.0,
            altitude: 35.0,
            verticalAccuracy: 1.5,
            speed: 15.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 30.0,
            meanSeaLevelAccuracy: 1.2
        }
    },
    'Switzerland': {
        locale: 'de-CH',
        country: 'CH',
        langCode: 'de',
        timezone: 'Europe/Zurich',
        displayLang: 'German',
        mcc_mnc: '22801',
        mcc: 228,
        mnc: 1,
        operatorName: 'Swisscom',
        mockLocationData: {
            latitude: 47.3769,
            longitude: 8.5417,
            city: 'Zurich',
            accuracy: 5.0,
            altitude: 408.0,
            verticalAccuracy: 2.0,
            speed: 12.0,
            speedAccuracy: 1.8,
            meanSeaLevel: 400.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Angola': {
        locale: 'pt-AO',
        country: 'AO',
        langCode: 'pt',
        timezone: 'Africa/Luanda',
        displayLang: 'Portuguese',
        mcc_mnc: '63102',
        mcc: 631,
        mnc: 2,
        operatorName: 'Unitel',
        mockLocationData: {
            latitude: -8.8383,
            longitude: 13.2344,
            city: 'Luanda',
            accuracy: 15.0,
            altitude: 6.0,
            verticalAccuracy: 7.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 3.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Ethiopia': {
        locale: 'am-ET',
        country: 'ET',
        langCode: 'am',
        timezone: 'Africa/Addis_Ababa',
        displayLang: 'Amharic',
        mcc_mnc: '63601',
        mcc: 636,
        mnc: 1,
        operatorName: 'Ethio Telecom',
        mockLocationData: {
            latitude: 9.0192,
            longitude: 38.7525,
            city: 'Addis Ababa',
            accuracy: 20.0,
            altitude: 2355.0,
            verticalAccuracy: 10.0,
            speed: 10.0,
            speedAccuracy: 4.0,
            meanSeaLevel: 2350.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'South Africa': {
        locale: 'en-ZA',
        country: 'ZA',
        langCode: 'en',
        timezone: 'Africa/Johannesburg',
        displayLang: 'English',
        mcc_mnc: '65501',
        mcc: 655,
        mnc: 1,
        operatorName: 'Vodacom',
        mockLocationData: {
            latitude: -26.2041,
            longitude: 28.0473,
            city: 'Johannesburg',
            accuracy: 8.0,
            altitude: 1753.0,
            verticalAccuracy: 4.0,
            speed: 15.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 1745.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Kenya': {
        locale: 'en-KE',
        country: 'KE',
        langCode: 'en',
        timezone: 'Africa/Nairobi',
        displayLang: 'English',
        mcc_mnc: '63907',
        mcc: 639,
        mnc: 7,
        operatorName: 'Safaricom',
        mockLocationData: {
            latitude: -1.2921,
            longitude: 36.8219,
            city: 'Nairobi',
            accuracy: 12.0,
            altitude: 1795.0,
            verticalAccuracy: 6.0,
            speed: 10.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 1790.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Tanzania': {
        locale: 'sw-TZ',
        country: 'TZ',
        langCode: 'sw',
        timezone: 'Africa/Dar_es_Salaam',
        displayLang: 'Swahili',
        mcc_mnc: '64002',
        mcc: 640,
        mnc: 2,
        operatorName: 'Vodacom Tanzania',
        mockLocationData: {
            latitude: -6.8235,
            longitude: 39.2695,
            city: 'Dar es Salaam',
            accuracy: 15.0,
            altitude: 10.0,
            verticalAccuracy: 7.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Myanmar (Burma)': {
        locale: 'my-MM',
        country: 'MM',
        langCode: 'my',
        timezone: 'Asia/Yangon',
        displayLang: 'Burmese',
        mcc_mnc: '41401',
        mcc: 414,
        mnc: 1,
        operatorName: 'MPT',
        mockLocationData: {
            latitude: 16.8409,
            longitude: 96.1735,
            city: 'Yangon',
            accuracy: 10.0,
            altitude: 15.0,
            verticalAccuracy: 4.0,
            speed: 7.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 10.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Uganda': {
        locale: 'en-UG',
        country: 'UG',
        langCode: 'en',
        timezone: 'Africa/Kampala',
        displayLang: 'English',
        mcc_mnc: '64110',
        mcc: 641,
        mnc: 10,
        operatorName: 'MTN Uganda',
        mockLocationData: {
            latitude: 0.3476,
            longitude: 32.5825,
            city: 'Kampala',
            accuracy: 15.0,
            altitude: 1200.0,
            verticalAccuracy: 7.0,
            speed: 10.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 1195.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Afghanistan': {
        locale: 'ps-AF',
        country: 'AF',
        langCode: 'ps',
        timezone: 'Asia/Kabul',
        displayLang: 'Pashto',
        mcc_mnc: '41201',
        mcc: 412,
        mnc: 1,
        operatorName: 'Roshan',
        mockLocationData: {
            latitude: 34.5553,
            longitude: 69.2075,
            city: 'Kabul',
            accuracy: 20.0,
            altitude: 1791.0,
            verticalAccuracy: 10.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 1780.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'Ghana': {
        locale: 'en-GH',
        country: 'GH',
        langCode: 'en',
        timezone: 'Africa/Accra',
        displayLang: 'English',
        mcc_mnc: '62001',
        mcc: 620,
        mnc: 1,
        operatorName: 'MTN Ghana',
        mockLocationData: {
            latitude: 5.6037,
            longitude: -0.1870,
            city: 'Accra',
            accuracy: 12.0,
            altitude: 61.0,
            verticalAccuracy: 5.0,
            speed: 10.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 55.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Mozambique': {
        locale: 'pt-MZ',
        country: 'MZ',
        langCode: 'pt',
        timezone: 'Africa/Maputo',
        displayLang: 'Portuguese',
        mcc_mnc: '64304',
        mcc: 643,
        mnc: 4,
        operatorName: 'Vodacom Mozambique',
        mockLocationData: {
            latitude: -25.9653,
            longitude: 32.5892,
            city: 'Maputo',
            accuracy: 15.0,
            altitude: 47.0,
            verticalAccuracy: 7.0,
            speed: 7.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 40.0,
            meanSeaLevelAccuracy: 3.0
        }
    },
    'Cameroon': {
        locale: 'fr-CM',
        country: 'CM',
        langCode: 'fr',
        timezone: 'Africa/Douala',
        displayLang: 'French',
        mcc_mnc: '62401',
        mcc: 624,
        mnc: 1,
        operatorName: 'MTN Cameroon',
        mockLocationData: {
            latitude: 4.0450,
            longitude: 9.7020,
            city: 'Douala',
            accuracy: 12.0,
            altitude: 13.0,
            verticalAccuracy: 5.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 10.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Mali': {
        locale: 'fr-ML',
        country: 'ML',
        langCode: 'fr',
        timezone: 'Africa/Bamako',
        displayLang: 'French',
        mcc_mnc: '61001',
        mcc: 610,
        mnc: 1,
        operatorName: 'Malitel',
        mockLocationData: {
            latitude: 12.6392,
            longitude: -8.0029,
            city: 'Bamako',
            accuracy: 18.0,
            altitude: 350.0,
            verticalAccuracy: 8.0,
            speed: 10.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 345.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Burkina Faso': {
        locale: 'fr-BF',
        country: 'BF',
        langCode: 'fr',
        timezone: 'Africa/Ouagadougou',
        displayLang: 'French',
        mcc_mnc: '61301',
        mcc: 613,
        mnc: 1,
        operatorName: 'Telecel Faso',
        mockLocationData: {
            latitude: 12.3714,
            longitude: -1.5197,
            city: 'Ouagadougou',
            accuracy: 15.0,
            altitude: 300.0,
            verticalAccuracy: 7.0,
            speed: 9.0,
            speedAccuracy: 2.8,
            meanSeaLevel: 295.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Madagascar': {
        locale: 'fr-MG',
        country: 'MG',
        langCode: 'fr',
        timezone: 'Indian/Antananarivo',
        displayLang: 'French',
        mcc_mnc: '64601',
        mcc: 646,
        mnc: 1,
        operatorName: 'Orange Madagascar',
        mockLocationData: {
            latitude: -18.9137,
            longitude: 47.5361,
            city: 'Antananarivo',
            accuracy: 20.0,
            altitude: 1280.0,
            verticalAccuracy: 9.0,
            speed: 8.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 1270.0,
            meanSeaLevelAccuracy: 4.5
        }
    },
    'Niger': {
        locale: 'fr-NE',
        country: 'NE',
        langCode: 'fr',
        timezone: 'Africa/Niamey',
        displayLang: 'French',
        mcc_mnc: '61403',
        mcc: 614,
        mnc: 3,
        operatorName: 'Airtel Niger',
        mockLocationData: {
            latitude: 13.5116,
            longitude: 2.1246,
            city: 'Niamey',
            accuracy: 18.0,
            altitude: 215.0,
            verticalAccuracy: 8.0,
            speed: 10.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 210.0,
            meanSeaLevelAccuracy: 4.0
        }
    },
    'Libya': {
        locale: 'ar-LY',
        country: 'LY',
        langCode: 'ar',
        timezone: 'Africa/Tripoli',
        displayLang: 'Arabic',
        mcc_mnc: '60601',
        mcc: 606,
        mnc: 1,
        operatorName: 'Libyana',
        mockLocationData: {
            latitude: 32.8872,
            longitude: 13.1913,
            city: 'Tripoli',
            accuracy: 15.0,
            altitude: 10.0,
            verticalAccuracy: 7.0,
            speed: 12.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Panama': {
        locale: 'es-PA',
        country: 'PA',
        langCode: 'es',
        timezone: 'America/Panama',
        displayLang: 'Spanish',
        mcc_mnc: '71001',
        mcc: 710,
        mnc: 1,
        operatorName: 'Cable & Wireless Panama',
        mockLocationData: {
            latitude: 8.9824,
            longitude: -79.5199,
            city: 'Panama City',
            accuracy: 8.0,
            altitude: 60.0,
            verticalAccuracy: 3.5,
            speed: 10.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 55.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Uruguay': {
        locale: 'es-UY',
        country: 'UY',
        langCode: 'es',
        timezone: 'America/Montevideo',
        displayLang: 'Spanish',
        mcc_mnc: '74801',
        mcc: 748,
        mnc: 1,
        operatorName: 'Antel',
        mockLocationData: {
            latitude: -34.9033,
            longitude: -56.1882,
            city: 'Montevideo',
            accuracy: 7.0,
            altitude: 43.0,
            verticalAccuracy: 3.0,
            speed: 12.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 40.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Croatia': {
        locale: 'hr-HR',
        country: 'HR',
        langCode: 'hr',
        timezone: 'Europe/Zagreb',
        displayLang: 'Croatian',
        mcc_mnc: '21901',
        mcc: 219,
        mnc: 1,
        operatorName: 'T-Hrvatski Telekom',
        mockLocationData: {
            latitude: 45.8150,
            longitude: 15.9819,
            city: 'Zagreb',
            accuracy: 6.0,
            altitude: 122.0,
            verticalAccuracy: 2.8,
            speed: 10.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 115.0,
            meanSeaLevelAccuracy: 2.5
        }
    },
    'Cuba': {
        locale: 'es-CU',
        country: 'CU',
        langCode: 'es',
        timezone: 'America/Havana',
        displayLang: 'Spanish',
        mcc_mnc: '36801',
        mcc: 368,
        mnc: 1,
        operatorName: 'ETECSA',
        mockLocationData: {
            latitude: 23.1136,
            longitude: -82.3666,
            city: 'Havana',
            accuracy: 15.0,
            altitude: 50.0,
            verticalAccuracy: 7.0,
            speed: 8.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 45.0,
            meanSeaLevelAccuracy: 3.0
        }
    },
    'Bolivia': {
        locale: 'es-BO',
        country: 'BO',
        langCode: 'es',
        timezone: 'America/La_Paz',
        displayLang: 'Spanish',
        mcc_mnc: '73602',
        mcc: 736,
        mnc: 2,
        operatorName: 'Entel',
        mockLocationData: {
            latitude: -16.5000,
            longitude: -68.1500,
            city: 'La Paz',
            accuracy: 15.0,
            altitude: 3640.0,
            verticalAccuracy: 7.0,
            speed: 10.0,
            speedAccuracy: 3.5,
            meanSeaLevel: 3630.0,
            meanSeaLevelAccuracy: 5.0
        }
    },
    'Tunisia': {
        locale: 'ar-TN',
        country: 'TN',
        langCode: 'ar',
        timezone: 'Africa/Tunis',
        displayLang: 'Arabic',
        mcc_mnc: '60502',
        mcc: 605,
        mnc: 2,
        operatorName: 'Ooredoo Tunisia',
        mockLocationData: {
            latitude: 36.8065,
            longitude: 10.1815,
            city: 'Tunis',
            accuracy: 9.0,
            altitude: 4.0,
            verticalAccuracy: 4.0,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 2.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Czechia': {
        locale: 'cs-CZ',
        country: 'CZ',
        langCode: 'cs',
        timezone: 'Europe/Prague',
        displayLang: 'Czech',
        mcc_mnc: '23003',
        mcc: 230,
        mnc: 3,
        operatorName: 'Vodafone Czech Republic',
        mockLocationData: {
            latitude: 50.0755,
            longitude: 14.4378,
            city: 'Prague',
            accuracy: 7.0,
            altitude: 235.0,
            verticalAccuracy: 3.0,
            speed: 15.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 230.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Dominican Republic': {
        locale: 'es-DO',
        country: 'DO',
        langCode: 'es',
        timezone: 'America/Santo_Domingo',
        displayLang: 'Spanish',
        mcc_mnc: '37001',
        mcc: 370,
        mnc: 1,
        operatorName: 'Claro Dominicana',
        mockLocationData: {
            latitude: 18.4861,
            longitude: -69.9312,
            city: 'Santo Domingo',
            accuracy: 10.0,
            altitude: 14.0,
            verticalAccuracy: 4.5,
            speed: 10.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 10.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Azerbaijan': {
        locale: 'az-AZ',
        country: 'AZ',
        langCode: 'az',
        timezone: 'Asia/Baku',
        displayLang: 'Azerbaijani',
        mcc_mnc: '40001',
        mcc: 400,
        mnc: 1,
        operatorName: 'Azercell',
        mockLocationData: {
            latitude: 40.4093,
            longitude: 49.8671,
            city: 'Baku',
            accuracy: 8.0,
            altitude: 10.0,
            verticalAccuracy: 3.5,
            speed: 15.0,
            speedAccuracy: 2.8,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'Singapore': {
        locale: 'en-SG',
        country: 'SG',
        langCode: 'en',
        timezone: 'Asia/Singapore',
        displayLang: 'English',
        mcc_mnc: '52501',
        mcc: 525,
        mnc: 1,
        operatorName: 'Singtel',
        mockLocationData: {
            latitude: 1.3521,
            longitude: 103.8198,
            city: 'Singapore',
            accuracy: 3.0,
            altitude: 15.0,
            verticalAccuracy: 1.2,
            speed: 8.0,
            speedAccuracy: 1.0,
            meanSeaLevel: 10.0,
            meanSeaLevelAccuracy: 0.8
        }
    },
    'Denmark': {
        locale: 'da-DK',
        country: 'DK',
        langCode: 'da',
        timezone: 'Europe/Copenhagen',
        displayLang: 'Danish',
        mcc_mnc: '23801',
        mcc: 238,
        mnc: 1,
        operatorName: 'TDC',
        mockLocationData: {
            latitude: 55.6761,
            longitude: 12.5683,
            city: 'Copenhagen',
            accuracy: 5.0,
            altitude: 10.0,
            verticalAccuracy: 2.0,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Finland': {
        locale: 'fi-FI',
        country: 'FI',
        langCode: 'fi',
        timezone: 'Europe/Helsinki',
        displayLang: 'Finnish',
        mcc_mnc: '24405',
        mcc: 244,
        mnc: 5,
        operatorName: 'Elisa',
        mockLocationData: {
            latitude: 60.1695,
            longitude: 24.9354,
            city: 'Helsinki',
            accuracy: 7.0,
            altitude: 20.0,
            verticalAccuracy: 3.0,
            speed: 15.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 15.0,
            meanSeaLevelAccuracy: 2.0
        }
    },
    'New Zealand': {
        locale: 'en-NZ',
        country: 'NZ',
        langCode: 'en',
        timezone: 'Pacific/Auckland',
        displayLang: 'English',
        mcc_mnc: '53005',
        mcc: 530,
        mnc: 5,
        operatorName: 'Vodafone NZ',
        mockLocationData: {
            latitude: -36.8485,
            longitude: 174.7633,
            city: 'Auckland',
            accuracy: 6.0,
            altitude: 10.0,
            verticalAccuracy: 2.5,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 5.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Kuwait': {
        locale: 'ar-KW',
        country: 'KW',
        langCode: 'ar',
        timezone: 'Asia/Kuwait',
        displayLang: 'Arabic',
        mcc_mnc: '41902',
        mcc: 419,
        mnc: 2,
        operatorName: 'Zain Kuwait',
        mockLocationData: {
            latitude: 29.3759,
            longitude: 47.9774,
            city: 'Kuwait City',
            accuracy: 8.0,
            altitude: 2.0,
            verticalAccuracy: 3.5,
            speed: 18.0,
            speedAccuracy: 3.0,
            meanSeaLevel: 1.0,
            meanSeaLevelAccuracy: 1.2
        }
    },
    'Costa Rica': {
        locale: 'es-CR',
        country: 'CR',
        langCode: 'es',
        timezone: 'America/Costa_Rica',
        displayLang: 'Spanish',
        mcc_mnc: '71201',
        mcc: 712,
        mnc: 1,
        operatorName: 'ICE',
        mockLocationData: {
            latitude: 9.9281,
            longitude: -84.0907,
            city: 'San José',
            accuracy: 10.0,
            altitude: 1172.0,
            verticalAccuracy: 5.0,
            speed: 10.0,
            speedAccuracy: 2.5,
            meanSeaLevel: 1165.0,
            meanSeaLevelAccuracy: 3.5
        }
    },
    'Norway': {
        locale: 'nb-NO',
        country: 'NO',
        langCode: 'nb',
        timezone: 'Europe/Oslo',
        displayLang: 'Norwegian',
        mcc_mnc: '24201',
        mcc: 242,
        mnc: 1,
        operatorName: 'Telenor',
        mockLocationData: {
            latitude: 59.9139,
            longitude: 10.7522,
            city: 'Oslo',
            accuracy: 6.0,
            altitude: 23.0,
            verticalAccuracy: 2.5,
            speed: 12.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 18.0,
            meanSeaLevelAccuracy: 1.5
        }
    },
    'Ireland': {
        locale: 'en-IE',
        country: 'IE',
        langCode: 'en',
        timezone: 'Europe/Dublin',
        displayLang: 'English',
        mcc_mnc: '27203',
        mcc: 272,
        mnc: 3,
        operatorName: 'Vodafone Ireland',
        mockLocationData: {
            latitude: 53.3498,
            longitude: -6.2603,
            city: 'Dublin',
            accuracy: 5.0,
            altitude: 20.0,
            verticalAccuracy: 2.0,
            speed: 10.0,
            speedAccuracy: 1.5,
            meanSeaLevel: 15.0,
            meanSeaLevelAccuracy: 1.0
        }
    },
    'Hong Kong': {
        locale: 'en-HK',
        country: 'HK',
        langCode: 'en',
        timezone: 'Asia/Hong_Kong',
        displayLang: 'English',
        mcc_mnc: '45412',
        mcc: 454,
        mnc: 12,
        operatorName: 'SmarTone',
        mockLocationData: {
            latitude: 22.3193,
            longitude: 114.1694,
            city: 'Hong Kong',
            accuracy: 4.0,
            altitude: 35.0,
            verticalAccuracy: 1.5,
            speed: 15.0,
            speedAccuracy: 2.0,
            meanSeaLevel: 30.0,
            meanSeaLevelAccuracy: 1.2
        }
    },
    'Switzerland': {
        locale: 'de-CH',
        country: 'CH',
        langCode: 'de',
        timezone: 'Europe/Zurich',
        displayLang: 'German',
        mcc_mnc: '22801',
        mcc: 228,
        mnc: 1,
        operatorName: 'Swisscom',
        mockLocationData: {
            latitude: 47.3769,
            longitude: 8.5417,
            city: 'Zurich',
            accuracy: 5.0,
            altitude: 408.0,
            verticalAccuracy: 2.0,
            speed: 12.0,
            speedAccuracy: 1.8,
            meanSeaLevel: 400.0,
            meanSeaLevelAccuracy: 2.5
        }
    }
};

function multipleUnpining() {
    setTimeout(function () {
        send("MultipleUnpinning start loading");
        Java.perform(function () {
            send("in Java perform Loading MultipleUnpinning");
            console.log('');
            console.log('======');
            console.log('[#] Android Bypass for various Certificate Pinning methods [#]');
            console.log('======');


            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');

            // TrustManager (Android < 7) //
            ////////////////////////////////
            var TrustManager = Java.registerClass({
                // Implement a custom TrustManager
                name: 'dev.asd.test.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) { },
                    checkServerTrusted: function (chain, authType) { },
                    getAcceptedIssuers: function () { return []; }
                }
            });
            // Prepare the TrustManager array to pass to SSLContext.init()
            var TrustManagers = [TrustManager.$new()];
            // Get a handle on the init() on the SSLContext class
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
            try {
                // Override the init method, specifying the custom TrustManager
                SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
                    console.log('[+] Bypassing Trustmanager (Android < 7) pinner');
                    SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
                };
            } catch (err) {
                console.log('[-] TrustManager (Android < 7) pinner not found');
                //console.log(err);
            }




            // OkHTTPv3 (quadruple bypass) //
            /////////////////////////////////
            try {
                // Bypass OkHTTPv3 {1}
                var okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');
                okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                    console.log('[+] Bypassing OkHTTPv3 {1}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] OkHTTPv3 {1} pinner not found');
                //console.log(err);
            }
            try {
                // Bypass OkHTTPv3 {2}
                // This method of CertificatePinner.check is deprecated but could be found in some old Android apps
                var okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');
                okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
                    console.log('[+] Bypassing OkHTTPv3 {2}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] OkHTTPv3 {2} pinner not found');
                //console.log(err);
            }
            try {
                // Bypass OkHTTPv3 {3}
                var okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');
                okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (a, b) {
                    console.log('[+] Bypassing OkHTTPv3 {3}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] OkHTTPv3 {3} pinner not found');
                //console.log(err);
            }
            try {
                // Bypass OkHTTPv3 {4}
                var okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner');
                //okhttp3_Activity_4['check$okhttp'].implementation = function(a, b) {
                okhttp3_Activity_4.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function (a, b) {
                    console.log('[+] Bypassing OkHTTPv3 {4}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] OkHTTPv3 {4} pinner not found');
                //console.log(err);
            }




            // Trustkit (triple bypass) //
            //////////////////////////////
            try {
                // Bypass Trustkit {1}
                var trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
                trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                    console.log('[+] Bypassing Trustkit {1}: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Trustkit {1} pinner not found');
                //console.log(err);
            }
            try {
                // Bypass Trustkit {2}
                var trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
                trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                    console.log('[+] Bypassing Trustkit {2}: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Trustkit {2} pinner not found');
                //console.log(err);
            }
            try {
                // Bypass Trustkit {3}
                var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
                trustkit_PinningTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function (chain, authType) {
                    console.log('[+] Bypassing Trustkit {3}');
                    //return;
                };
            } catch (err) {
                console.log('[-] Trustkit {3} pinner not found');
                //console.log(err);
            }




            // TrustManagerImpl (Android > 7) //
            ////////////////////////////////////
            try {
                // Bypass TrustManagerImpl (Android > 7) {1}
                var array_list = Java.use("java.util.ArrayList");
                var TrustManagerImpl_Activity_1 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl_Activity_1.checkTrustedRecursive.implementation = function (certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
                    console.log('[+] Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check: ' + host);
                    return array_list.$new();
                };
            } catch (err) {
                console.log('[-] TrustManagerImpl (Android > 7) checkTrustedRecursive check not found');
                //console.log(err);
            }
            try {
                // Bypass TrustManagerImpl (Android > 7) {2} (probably no more necessary)
                var TrustManagerImpl_Activity_2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl_Activity_2.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    console.log('[+] Bypassing TrustManagerImpl (Android > 7) verifyChain check: ' + host);
                    return untrustedChain;
                };
            } catch (err) {
                console.log('[-] TrustManagerImpl (Android > 7) verifyChain check not found');
                //console.log(err);
            }





            // Appcelerator Titanium PinningTrustManager //
            ///////////////////////////////////////////////
            try {
                var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
                appcelerator_PinningTrustManager.checkServerTrusted.implementation = function (chain, authType) {
                    console.log('[+] Bypassing Appcelerator PinningTrustManager');
                    return;
                };
            } catch (err) {
                console.log('[-] Appcelerator PinningTrustManager pinner not found');
                //console.log(err);
            }




            // Fabric PinningTrustManager //
            ////////////////////////////////
            try {
                var fabric_PinningTrustManager = Java.use('io.fabric.sdk.android.services.network.PinningTrustManager');
                fabric_PinningTrustManager.checkServerTrusted.implementation = function (chain, authType) {
                    console.log('[+] Bypassing Fabric PinningTrustManager');
                    return;
                };
            } catch (err) {
                console.log('[-] Fabric PinningTrustManager pinner not found');
                //console.log(err);
            }




            // OpenSSLSocketImpl Conscrypt (double bypass) //
            /////////////////////////////////////////////////
            try {
                var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
                OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
                    console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt {1}');
                };
            } catch (err) {
                console.log('[-] OpenSSLSocketImpl Conscrypt {1} pinner not found');
                //console.log(err);        
            }
            try {
                var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
                OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certChain, authMethod) {
                    console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt {2}');
                };
            } catch (err) {
                console.log('[-] OpenSSLSocketImpl Conscrypt {2} pinner not found');
                //console.log(err);        
            }




            // OpenSSLEngineSocketImpl Conscrypt //
            ///////////////////////////////////////
            try {
                var OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
                OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function (a, b) {
                    console.log('[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
                };
            } catch (err) {
                console.log('[-] OpenSSLEngineSocketImpl Conscrypt pinner not found');
                //console.log(err);
            }




            // OpenSSLSocketImpl Apache Harmony //
            //////////////////////////////////////
            try {
                var OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
                OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
                    console.log('[+] Bypassing OpenSSLSocketImpl Apache Harmony');
                };
            } catch (err) {
                console.log('[-] OpenSSLSocketImpl Apache Harmony pinner not found');
                //console.log(err);      
            }




            // PhoneGap sslCertificateChecker //
            ////////////////////////////////////
            try {
                var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
                phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
                    console.log('[+] Bypassing PhoneGap sslCertificateChecker: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] PhoneGap sslCertificateChecker pinner not found');
                //console.log(err);
            }




            // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass) //
            ////////////////////////////////////////////////////////////////////
            try {
                // Bypass IBM MobileFirst {1}
                var WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
                WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function (cert) {
                    console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + cert);
                    return;
                };
            } catch (err) {
                console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found');
                //console.log(err);
            }
            try {
                // Bypass IBM MobileFirst {2}
                var WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
                WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function (cert) {
                    console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: ' + cert);
                    return;
                };
            } catch (err) {
                console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {2} pinner not found');
                //console.log(err);
            }




            // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass) //
            ///////////////////////////////////////////////////////////////////////////////////////////////////////
            try {
                // Bypass IBM WorkLight {1}
                var worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
                worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (a, b) {
                    console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found');
                //console.log(err);
            }
            try {
                // Bypass IBM WorkLight {2}
                var worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
                worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                    console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {2} pinner not found');
                //console.log(err);
            }
            try {
                // Bypass IBM WorkLight {3}
                var worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
                worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (a, b) {
                    console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {3} pinner not found');
                //console.log(err);
            }
            try {
                // Bypass IBM WorkLight {4}
                var worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
                worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                    console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {4} pinner not found');
                //console.log(err);
            }




            // Conscrypt CertPinManager //
            //////////////////////////////
            try {
                var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
                conscrypt_CertPinManager_Activity.checkChainPinning.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                    console.log('[+] Bypassing Conscrypt CertPinManager: ' + a);
                    //return;
                    return true;
                };
            } catch (err) {
                console.log('[-] Conscrypt CertPinManager pinner not found');
                //console.log(err);
            }




            // Conscrypt CertPinManager (Legacy) //
            ///////////////////////////////////////
            try {
                var legacy_conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
                legacy_conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                    console.log('[+] Bypassing Conscrypt CertPinManager (Legacy): ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Conscrypt CertPinManager (Legacy) pinner not found');
                //console.log(err);
            }




            // CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager //
            ///////////////////////////////////////////////////////////////////////////////////
            try {
                var cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
                cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                    console.log('[+] Bypassing CWAC-Netsecurity CertPinManager: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] CWAC-Netsecurity CertPinManager pinner not found');
                //console.log(err);
            }




            // Worklight Androidgap WLCertificatePinningPlugin //
            /////////////////////////////////////////////////////
            try {
                var androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
                androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
                    console.log('[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Worklight Androidgap WLCertificatePinningPlugin pinner not found');
                //console.log(err);
            }




            // Netty FingerprintTrustManagerFactory //
            //////////////////////////////////////////
            try {
                var netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
                //NOTE: sometimes this below implementation could be useful 
                //var netty_FingerprintTrustManagerFactory = Java.use('org.jboss.netty.handler.ssl.util.FingerprintTrustManagerFactory');
                netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function (type, chain) {
                    console.log('[+] Bypassing Netty FingerprintTrustManagerFactory');
                };
            } catch (err) {
                console.log('[-] Netty FingerprintTrustManagerFactory pinner not found');
                //console.log(err);
            }




            // Squareup CertificatePinner [OkHTTP<v3] (double bypass) //
            ////////////////////////////////////////////////////////////
            try {
                // Bypass Squareup CertificatePinner  {1}
                var Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
                Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
                    console.log('[+] Bypassing Squareup CertificatePinner {1}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] Squareup CertificatePinner {1} pinner not found');
                //console.log(err);
            }
            try {
                // Bypass Squareup CertificatePinner {2}
                var Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
                Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                    console.log('[+] Bypassing Squareup CertificatePinner {2}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] Squareup CertificatePinner {2} pinner not found');
                //console.log(err);
            }




            // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass) //
            /////////////////////////////////////////////////////////////
            try {
                // Bypass Squareup OkHostnameVerifier {1}
                var Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
                Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                    console.log('[+] Bypassing Squareup OkHostnameVerifier {1}: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Squareup OkHostnameVerifier check not found');
                //console.log(err);
            }
            try {
                // Bypass Squareup OkHostnameVerifier {2}
                var Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
                Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                    console.log('[+] Bypassing Squareup OkHostnameVerifier {2}: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Squareup OkHostnameVerifier check not found');
                //console.log(err);
            }




            // Android WebViewClient (quadruple bypass) //
            //////////////////////////////////////////////
            try {
                // Bypass WebViewClient {1} (deprecated from Android 6)
                var AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
                AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
                    console.log('[+] Bypassing Android WebViewClient check {1}');
                };
            } catch (err) {
                console.log('[-] Android WebViewClient {1} check not found');
                //console.log(err)
            }
            try {
                // Bypass WebViewClient {2}
                var AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
                AndroidWebViewClient_Activity_2.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function (obj1, obj2, obj3) {
                    console.log('[+] Bypassing Android WebViewClient check {2}');
                };
            } catch (err) {
                console.log('[-] Android WebViewClient {2} check not found');
                //console.log(err)
            }
            try {
                // Bypass WebViewClient {3}
                var AndroidWebViewClient_Activity_3 = Java.use('android.webkit.WebViewClient');
                AndroidWebViewClient_Activity_3.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function (obj1, obj2, obj3, obj4) {
                    console.log('[+] Bypassing Android WebViewClient check {3}');
                };
            } catch (err) {
                console.log('[-] Android WebViewClient {3} check not found');
                //console.log(err)
            }
            try {
                // Bypass WebViewClient {4}
                var AndroidWebViewClient_Activity_4 = Java.use('android.webkit.WebViewClient');
                AndroidWebViewClient_Activity_4.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function (obj1, obj2, obj3) {
                    console.log('[+] Bypassing Android WebViewClient check {4}');
                };
            } catch (err) {
                console.log('[-] Android WebViewClient {4} check not found');
                //console.log(err)
            }




            // Apache Cordova WebViewClient //
            //////////////////////////////////
            try {
                var CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
                CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
                    console.log('[+] Bypassing Apache Cordova WebViewClient check');
                    obj3.proceed();
                };
            } catch (err) {
                console.log('[-] Apache Cordova WebViewClient check not found');
                //console.log(err);
            }




            // Boye AbstractVerifier //
            ///////////////////////////
            try {
                var boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
                boye_AbstractVerifier.verify.implementation = function (host, ssl) {
                    console.log('[+] Bypassing Boye AbstractVerifier check: ' + host);
                };
            } catch (err) {
                console.log('[-] Boye AbstractVerifier check not found');
                //console.log(err);
            }




            // Apache AbstractVerifier //
            /////////////////////////////
            try {
                var apache_AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
                apache_AbstractVerifier.verify.implementation = function (a, b, c, d) {
                    console.log('[+] Bypassing Apache AbstractVerifier check: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] Apache AbstractVerifier check not found');
                //console.log(err);
            }




            // Chromium Cronet //
            /////////////////////    
            try {
                var CronetEngineBuilderImpl_Activity = Java.use("org.chromium.net.impl.CronetEngineBuilderImpl");
                // Setting argument to TRUE (default is TRUE) to disable Public Key pinning for local trust anchors
                CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.overload('boolean').implementation = function (a) {
                    console.log("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet");
                    var cronet_obj_1 = CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                    return cronet_obj_1;
                };
                // Bypassing Chromium Cronet pinner
                CronetEngine_Activity.addPublicKeyPins.overload('java.lang.String', 'java.util.Set', 'boolean', 'java.util.Date').implementation = function (hostName, pinsSha256, includeSubdomains, expirationDate) {
                    console.log("[+] Bypassing Chromium Cronet pinner: " + hostName);
                    var cronet_obj_2 = CronetEngine_Activity.addPublicKeyPins.call(this, hostName, pinsSha256, includeSubdomains, expirationDate);
                    return cronet_obj_2;
                };
            } catch (err) {
                console.log('[-] Chromium Cronet pinner not found')
                //console.log(err);
            }

            // Flutter Pinning packages http_certificate_pinning and ssl_pinning_plugin (double bypass) //
            //////////////////////////////////////////////////////////////////////////////////////////////
            try {
                // Bypass HttpCertificatePinning.check {1}
                var HttpCertificatePinning_Activity = Java.use('diefferson.http_certificate_pinning.HttpCertificatePinning');
                HttpCertificatePinning_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c, d, e) {
                    console.log('[+] Bypassing Flutter HttpCertificatePinning : ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Flutter HttpCertificatePinning pinner not found');
                //console.log(err);
            }
            try {
                // Bypass SslPinningPlugin.check {2}
                var SslPinningPlugin_Activity = Java.use('com.macif.plugin.sslpinningplugin.SslPinningPlugin');
                SslPinningPlugin_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c, d, e) {
                    console.log('[+] Bypassing Flutter SslPinningPlugin: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Flutter SslPinningPlugin pinner not found');
                //console.log(err);
            }




            // Dynamic SSLPeerUnverifiedException Patcher                                //
            // An useful technique to bypass SSLPeerUnverifiedException failures raising //
            // when the Android app uses some uncommon SSL Pinning methods or an heavily //
            // code obfuscation. Inspired by an idea of: https://github.com/httptoolkit  //
            ///////////////////////////////////////////////////////////////////////////////
            function rudimentaryFix(typeName) {
                // This is a improvable rudimentary fix, if not works you can patch it manually
                if (typeName === undefined) {
                    return;
                } else if (typeName === 'boolean') {
                    return true;
                } else {
                    return null;
                }
            }
            try {
                var UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
                UnverifiedCertError.$init.implementation = function (str) {
                    console.log('\x1b[36m[!] Unexpected SSLPeerUnverifiedException occurred, trying to patch it dynamically...\x1b[0m');
                    try {
                        var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                        var exceptionStackIndex = stackTrace.findIndex(stack =>
                            stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                        );
                        // Retrieve the method raising the SSLPeerUnverifiedException
                        var callingFunctionStack = stackTrace[exceptionStackIndex + 1];
                        var className = callingFunctionStack.getClassName();
                        var methodName = callingFunctionStack.getMethodName();
                        var callingClass = Java.use(className);
                        var callingMethod = callingClass[methodName];
                        console.log('\x1b[36m[!] Attempting to bypass uncommon SSL Pinning method on: ' + className + '.' + methodName + '\x1b[0m');
                        // Skip it when already patched by Frida
                        if (callingMethod.implementation) {
                            return;
                        }
                        // Trying to patch the uncommon SSL Pinning method via implementation
                        var returnTypeName = callingMethod.returnType.type;
                        callingMethod.implementation = function () {
                            rudimentaryFix(returnTypeName);
                        };
                    } catch (e) {
                        // Dynamic patching via implementation does not works, then trying via function overloading
                        //console.log('[!] The uncommon SSL Pinning method has more than one overload); 
                        if (String(e).includes(".overload")) {
                            var splittedList = String(e).split(".overload");
                            for (let i = 2; i < splittedList.length; i++) {
                                var extractedOverload = splittedList[i].trim().split("(")[1].slice(0, -1).replaceAll("'", "");
                                // Check if extractedOverload has multiple arguments
                                if (extractedOverload.includes(",")) {
                                    // Go here if overloaded method has multiple arguments (NOTE: max 6 args are covered here)
                                    var argList = extractedOverload.split(", ");
                                    console.log('\x1b[36m[!] Attempting overload of ' + className + '.' + methodName + ' with arguments: ' + extractedOverload + '\x1b[0m');
                                    if (argList.length == 2) {
                                        callingMethod.overload(argList[0], argList[1]).implementation = function (a, b) {
                                            rudimentaryFix(returnTypeName);
                                        }
                                    } else if (argNum == 3) {
                                        callingMethod.overload(argList[0], argList[1], argList[2]).implementation = function (a, b, c) {
                                            rudimentaryFix(returnTypeName);
                                        }
                                    } else if (argNum == 4) {
                                        callingMethod.overload(argList[0], argList[1], argList[2], argList[3]).implementation = function (a, b, c, d) {
                                            rudimentaryFix(returnTypeName);
                                        }
                                    } else if (argNum == 5) {
                                        callingMethod.overload(argList[0], argList[1], argList[2], argList[3], argList[4]).implementation = function (a, b, c, d, e) {
                                            rudimentaryFix(returnTypeName);
                                        }
                                    } else if (argNum == 6) {
                                        callingMethod.overload(argList[0], argList[1], argList[2], argList[3], argList[4], argList[5]).implementation = function (a, b, c, d, e, f) {
                                            rudimentaryFix(returnTypeName);
                                        }
                                    }
                                    // Go here if overloaded method has a single argument
                                } else {
                                    callingMethod.overload(extractedOverload).implementation = function (a) {
                                        rudimentaryFix(returnTypeName);
                                    }
                                }
                            }
                        } else {
                            console.log('\x1b[36m[-] Failed to dynamically patch SSLPeerUnverifiedException ' + e + '\x1b[0m');
                        }
                    }
                    //console.log('\x1b[36m[+] SSLPeerUnverifiedException hooked\x1b[0m');
                    return this.$init(str);
                };
            } catch (err) {
                //console.log('\x1b[36m[-] SSLPeerUnverifiedException not found\x1b[0m');
                //console.log('\x1b[36m'+err+'\x1b[0m');
            }

        });
        send("Multiple Unpinning Loaded");

    }, 0);
}

// Trace all Start
var Color = {
    RESET: "\x1b[39;49;00m",
    Black: "0;01",
    Blue: "4;01",
    Cyan: "6;01",
    Gray: "7;11",
    Green: "2;01",
    Purple: "5;01",
    Red: "1;01",
    Yellow: "3;01",
    Light: {
        Black: "0;11",
        Blue: "4;11",
        Cyan: "6;11",
        Gray: "7;01",
        Green: "2;11",
        Purple: "5;11",
        Red: "1;11",
        Yellow: "3;11"
    }
};

/**
 *
 * @param input. 
 *      If an object is passed it will print as json 
 * @param kwargs  options map {
 *     -l level: string;   log/warn/error
 *     -i indent: boolean;     print JSON prettify
 *     -c color: @see ColorMap
 * }
 */
var LOG = function (input, kwargs) {
    kwargs = kwargs || {};
    var logLevel = kwargs['l'] || 'log',
        colorPrefix = '\x1b[3',
        colorSuffix = 'm';
    if (typeof input === 'object')
        input = JSON.stringify(input, null, kwargs['i'] ? 2 : null);
    if (kwargs['c'])
        input = colorPrefix + kwargs['c'] + colorSuffix + input + Color.RESET;
    console[logLevel](input);
};

var printBacktrace = function () {
    Java.perform(function () {
        var android_util_Log = Java.use('android.util.Log'),
            java_lang_Exception = Java.use('java.lang.Exception');
        // getting stacktrace by throwing an exception
        LOG(android_util_Log.getStackTraceString(java_lang_Exception.$new()), { c: Color.Gray });
    });
};

function traceClass(targetClass) {
    var hook;
    try {
        hook = Java.use(targetClass);
    } catch (e) {
        console.error("trace class failed", e);
        return;
    }

    var methods = hook.class.getDeclaredMethods();
    hook.$dispose();

    var parsedMethods = [];
    methods.forEach(function (method) {
        var methodStr = method.toString();
        var methodReplace = methodStr.replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
        parsedMethods.push(methodReplace);
    });

    uniqBy(parsedMethods, JSON.stringify).forEach(function (targetMethod) {
        traceMethod(targetClass + '.' + targetMethod);
    });
}

function traceMethod(targetClassMethod) {
    var delim = targetClassMethod.lastIndexOf('.');
    if (delim === -1)
        return;

    var targetClass = targetClassMethod.slice(0, delim);
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);

    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;

    send({ tracing: targetClassMethod, overloaded: overloadCount });

    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
            var log = { '#': targetClassMethod, args: [] };

            for (var j = 0; j < arguments.length; j++) {
                var arg = arguments[j];
                // quick&dirty fix for java.io.StringWriter char[].toString() impl because frida prints [object Object]
                if (j === 0 && arguments[j]) {
                    if (arguments[j].toString() === '[object Object]') {
                        var s = [];
                        for (var k = 0, l = arguments[j].length; k < l; k++) {
                            s.push(arguments[j][k]);
                        }
                        arg = s.join('');
                    }
                }
                log.args.push({ i: j, o: arg, s: arg ? arg.toString() : 'null' });
            }

            var retval;
            try {
                retval = this[targetMethod].apply(this, arguments); // might crash (Frida bug?)
                log.returns = { val: retval, str: retval ? retval.toString() : null };
            } catch (e) {
                console.error(e);
            }
            send(log);
            return retval;
        }
    }
}

// remove duplicates from array
function uniqBy(array, key) {
    var seen = {};
    return array.filter(function (item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}
// Trace all End

function anti_root() {
    Java.perform(function () {
        var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
            "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
        ];

        var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

        var RootProperties = {
            "ro.build.selinux": "1",
            "ro.debuggable": "0",
            "service.adb.root": "0",
            "ro.secure": "1"
        };

        var RootPropertiesKeys = [];

        for (var k in RootProperties) RootPropertiesKeys.push(k);

        var PackageManager = Java.use("android.app.ApplicationPackageManager");

        var Runtime = Java.use('java.lang.Runtime');

        var NativeFile = Java.use('java.io.File');

        var String = Java.use('java.lang.String');

        var SystemProperties = Java.use('android.os.SystemProperties');

        var BufferedReader = Java.use('java.io.BufferedReader');

        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

        var StringBuffer = Java.use('java.lang.StringBuffer');

        var loaded_classes = Java.enumerateLoadedClassesSync();

        send("Loaded " + loaded_classes.length + " classes!");

        var useKeyInfo = false;

        var useProcessManager = false;

        send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

        if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
            try {
                //useProcessManager = true;
                //var ProcessManager = Java.use('java.lang.ProcessManager');
            } catch (err) {
                send("ProcessManager Hook failed: " + err);
            }
        } else {
            send("ProcessManager hook not loaded");
        }

        var KeyInfo = null;

        if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
            try {
                //useKeyInfo = true;
                //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
            } catch (err) {
                send("KeyInfo Hook failed: " + err);
            }
        } else {
            send("KeyInfo hook not loaded");
        }

        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pname, flags) {
            var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
            if (shouldFakePackage) {
                send("Bypass root check for package: " + pname);
                pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
            }
            return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
        };

        NativeFile.exists.implementation = function () {
            var name = NativeFile.getName.call(this);
            var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
            if (shouldFakeReturn) {
                send("Bypass return value for binary: " + name);
                return false;
            } else {
                return this.exists.call(this);
            }
        };

        var exec = Runtime.exec.overload('[Ljava.lang.String;');
        var exec1 = Runtime.exec.overload('java.lang.String');
        var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
        var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
        var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
        var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

        exec5.implementation = function (cmd, env, dir) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec5.call(this, cmd, env, dir);
        };

        exec4.implementation = function (cmdarr, env, file) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec4.call(this, cmdarr, env, file);
        };

        exec3.implementation = function (cmdarr, envp) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec3.call(this, cmdarr, envp);
        };

        exec2.implementation = function (cmd, env) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec2.call(this, cmd, env);
        };

        exec.implementation = function (cmd) {
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    send("Bypass " + cmd + " command");
                    return exec.call(this, fakeCmd);
                }
                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
                if (cmd.indexOf("which su") != -1) {
                    let fakeCmd = 'pwd | grep zzzzz';
                    send("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec.call(this, cmd);
        };

        exec1.implementation = function (cmd) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd.indexOf("which su") != -1) {
                let fakeCmd = 'pwd | grep zzzzz';
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec1.call(this, cmd);
        };

        String.contains.implementation = function (name) {
            if (name == "test-keys") {
                send("Bypass test-keys check");
                return false;
            }
            return this.contains.call(this, name);
        };

        var get = SystemProperties.get.overload('java.lang.String');

        get.implementation = function (name) {
            if (RootPropertiesKeys.indexOf(name) != -1) {
                send("Bypass " + name);
                return RootProperties[name];
            }
            return this.get.call(this, name);
        };

        Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
            onEnter: function (args) {
                var path = Memory.readCString(args[0]);
                path = path.split("/");
                var executable = path[path.length - 1];
                var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
                if (shouldFakeReturn) {
                    Memory.writeUtf8String(args[0], "/notexists");
                    send("Bypass native fopen");
                }
            },
            onLeave: function (retval) {

            }
        });

        Interceptor.attach(Module.findExportByName("libc.so", "system"), {
            onEnter: function (args) {
                var cmd = Memory.readCString(args[0]);
                send("SYSTEM CMD: " + cmd);
                if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "grep");
                }
                if (cmd == "su") {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
                }
            },
            onLeave: function (retval) {

            }
        });

        /*
    
        TO IMPLEMENT:
    
        Exec Family
    
        int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
        int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
        int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execv(const char *path, char *const argv[]);
        int execve(const char *path, char *const argv[], char *const envp[]);
        int execvp(const char *file, char *const argv[]);
        int execvpe(const char *file, char *const argv[], char *const envp[]);
    
        */


        BufferedReader.readLine.overload('boolean').implementation = function () {
            var text = this.readLine.overload('boolean').call(this);
            if (text === null) {
                // just pass , i know it's ugly as hell but test != null won't work :(
            } else {
                var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
                if (shouldFakeRead) {
                    send("Bypass build.prop file read");
                    text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                }
            }
            return text;
        };

        var executeCommand = ProcessBuilder.command.overload('java.util.List');

        ProcessBuilder.start.implementation = function () {
            var cmd = this.command.call(this);
            var shouldModifyCommand = false;
            for (var i = 0; i < cmd.size(); i = i + 1) {
                var tmp_cmd = cmd.get(i).toString();
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                    shouldModifyCommand = true;
                }
            }
            if (shouldModifyCommand) {
                send("Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["grep"]);
                return this.start.call(this);
            }
            if (cmd.indexOf("su") != -1) {
                send("Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
                return this.start.call(this);
            }

            return this.start.call(this);
        };

        if (useProcessManager) {
            var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
            var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

            ProcManExec.implementation = function (cmd, env, workdir, redirectstderr) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
            };

            ProcManExecVariant.implementation = function (cmd, env, directory, stdin, stdout, stderr, redirect) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
            };
        }

        if (useKeyInfo) {
            KeyInfo.isInsideSecureHardware.implementation = function () {
                send("Bypass isInsideSecureHardware");
                return true;
            }
        }

    });

    const commonPaths = [
        "/data/local/bin/su",
        "/data/local/su",
        "/data/local/xbin/su",
        "/dev/com.koushikdutta.superuser.daemon/",
        "/sbin/su",
        "/system/app/Superuser.apk",
        "/system/bin/failsafe/su",
        "/system/bin/su",
        "/su/bin/su",
        "/system/etc/init.d/99SuperSUDaemon",
        "/system/sd/xbin/su",
        "/system/xbin/busybox",
        "/system/xbin/daemonsu",
        "/system/xbin/su",
        "/system/sbin/su",
        "/vendor/bin/su",
        "/cache/su",
        "/data/su",
        "/dev/su",
        "/system/bin/.ext/su",
        "/system/usr/we-need-root/su",
        "/system/app/Kinguser.apk",
        "/data/adb/magisk",
        "/sbin/.magisk",
        "/cache/.disable_magisk",
        "/dev/.magisk.unblock",
        "/cache/magisk.log",
        "/data/adb/magisk.img",
        "/data/adb/magisk.db",
        "/data/adb/magisk_simple",
        "/init.magisk.rc",
        "/system/xbin/ku.sud",
        "/data/adb/ksu",
        "/data/adb/ksud"
    ];

    const ROOTmanagementApp = [
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license",
        "com.dimonvideo.luckypatcher",
        "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine",
        "com.ramdroid.appquarantinepro",
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu"
    ];



    function stackTraceHere(isLog) {
        var Exception = Java.use('java.lang.Exception');
        var Log = Java.use('android.util.Log');
        var stackinfo = Log.getStackTraceString(Exception.$new())
        if (isLog) {
            console.log(stackinfo)
        } else {
            return stackinfo
        }
    }

    function stackTraceNativeHere(isLog) {
        var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join("\n\t");
        console.log(backtrace)
    }


    function bypassJavaFileCheck() {
        var UnixFileSystem = Java.use("java.io.UnixFileSystem")
        UnixFileSystem.checkAccess.implementation = function (file, access) {

            var stack = stackTraceHere(false)

            const filename = file.getAbsolutePath();

            if (filename.indexOf("magisk") >= 0) {
                console.log("Anti Root Detect - check file: " + filename)
                return false;
            }

            if (commonPaths.indexOf(filename) >= 0) {
                console.log("Anti Root Detect - check file: " + filename)
                return false;
            }

            return this.checkAccess(file, access)
        }
    }

    function bypassNativeFileCheck() {
        var fopen = Module.findExportByName("libc.so", "fopen")
        Interceptor.attach(fopen, {
            onEnter: function (args) {
                this.inputPath = args[0].readUtf8String()
            },
            onLeave: function (retval) {
                if (retval.toInt32() != 0) {
                    if (commonPaths.indexOf(this.inputPath) >= 0) {
                        console.log("Anti Root Detect - fopen : " + this.inputPath)
                        retval.replace(ptr(0x0))
                    }
                }
            }
        })

        var access = Module.findExportByName("libc.so", "access")
        Interceptor.attach(access, {
            onEnter: function (args) {
                this.inputPath = args[0].readUtf8String()
            },
            onLeave: function (retval) {
                if (retval.toInt32() == 0) {
                    if (commonPaths.indexOf(this.inputPath) >= 0) {
                        console.log("Anti Root Detect - access : " + this.inputPath)
                        retval.replace(ptr(-1))
                    }
                }
            }
        })
    }

    function setProp() {
        var Build = Java.use("android.os.Build")
        var TAGS = Build.class.getDeclaredField("TAGS")
        TAGS.setAccessible(true)
        TAGS.set(null, "release-keys")

        var FINGERPRINT = Build.class.getDeclaredField("FINGERPRINT")
        FINGERPRINT.setAccessible(true)
        FINGERPRINT.set(null, "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys")

        // Build.deriveFingerprint.inplementation = function(){
        //     var ret = this.deriveFingerprint() //该函数无法通过反射调用
        //     console.log(ret)
        //     return ret
        // }

        var system_property_get = Module.findExportByName("libc.so", "__system_property_get")
        Interceptor.attach(system_property_get, {
            onEnter(args) {
                this.key = args[0].readCString()
                this.ret = args[1]
            },
            onLeave(ret) {
                if (this.key == "ro.build.fingerprint") {
                    var tmp = "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys"
                    var p = Memory.allocUtf8String(tmp)
                    Memory.copy(this.ret, p, tmp.length + 1)
                }
            }
        })

    }

    //android.app.PackageManager
    function bypassRootAppCheck() {
        var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager")
        ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (str, i) {
            // console.log(str)
            if (ROOTmanagementApp.indexOf(str) >= 0) {
                console.log("Anti Root Detect - check package : " + str)
                str = "ashen.one.ye.not.found"
            }
            return this.getPackageInfo(str, i)
        }

        //shell pm check
    }

    function bypassShellCheck() {
        var String = Java.use('java.lang.String')

        var ProcessImpl = Java.use("java.lang.ProcessImpl")
        ProcessImpl.start.implementation = function (cmdarray, env, dir, redirects, redirectErrorStream) {

            if (cmdarray[0] == "mount") {
                console.log("Anti Root Detect - Shell : " + cmdarray.toString())
                arguments[0] = Java.array('java.lang.String', [String.$new("")])
                return ProcessImpl.start.apply(this, arguments)
            }

            if (cmdarray[0] == "getprop") {
                console.log("Anti Root Detect - Shell : " + cmdarray.toString())
                const prop = [
                    "ro.secure",
                    "ro.debuggable"
                ];
                if (prop.indexOf(cmdarray[1]) >= 0) {
                    arguments[0] = Java.array('java.lang.String', [String.$new("")])
                    return ProcessImpl.start.apply(this, arguments)
                }
            }

            if (cmdarray[0].indexOf("which") >= 0) {
                const prop = [
                    "su"
                ];
                if (prop.indexOf(cmdarray[1]) >= 0) {
                    console.log("Anti Root Detect - Shell : " + cmdarray.toString())
                    arguments[0] = Java.array('java.lang.String', [String.$new("")])
                    return ProcessImpl.start.apply(this, arguments)
                }
            }

            return ProcessImpl.start.apply(this, arguments)
        }
    }


    console.log("Attach");
    bypassNativeFileCheck();
    bypassJavaFileCheck();
    setProp();
    bypassRootAppCheck();
    bypassShellCheck();
}

function hook_reflection() {
    Java.perform(function () {

        var internalClasses = []; // uncomment this if you want no filtering!

        // var internalClasses = ["android.", "com.android", "java.lang", "java.io"]; // comment this for no filtering

        var classDef = Java.use('java.lang.Class');

        var classLoaderDef = Java.use('java.lang.ClassLoader');

        var forName = classDef.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader');

        var loadClass = classLoaderDef.loadClass.overload('java.lang.String', 'boolean');

        var getMethod = classDef.getMethod.overload('java.lang.String', '[Ljava.lang.Class;');

        // var newInstance = classDef.newInstance.overload();

        // newInstance.implementation = function () {
        //     send('[*] newInstance: ' + this.getName());
        //     var ret = newInstance.call(this);
        //     return ret;
        // };

        getMethod.implementation = function (param1, param2) {
            send('[*] Get Method : [' + param1 + ']');
            stackTrace();
            var ret = getMethod.call(this, param1, param2);
            return ret;
        };

        forName.implementation = function (class_name, flag, class_loader) {
            var isGood = true;
            for (var i = 0; i < internalClasses.length; i++) {
                if (class_name.startsWith(internalClasses[i])) {
                    isGood = false;
                }
            }
            if (isGood) {
                send("Reflection => forName => " + class_name);
                stackTrace();
            }
            return forName.call(this, class_name, flag, class_loader);
        }

        loadClass.implementation = function (class_name, resolve) {
            var isGood = true;
            for (var i = 0; i < internalClasses.length; i++) {
                if (class_name.startsWith(internalClasses[i])) {
                    isGood = false;
                }
            }
            if (isGood) {
                send("Reflection => loadClass => " + class_name);
                stackTrace();
            }
            return loadClass.call(this, class_name, resolve);
        }
    });
}

function hook_dexclassloader() {
    Java.perform(function () {
        //Create a Wapper of DexClassLoader
        var dexclassLoader = Java.use("dalvik.system.DexClassLoader");
        //hook its constructor $init, we will print out its four parameters.
        dexclassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            send("dexPath:" + dexPath);
            send("optimizedDirectory:" + optimizedDirectory);
            send("librarySearchPath:" + librarySearchPath);
            send("parent:" + parent);
            //Without breaking its original logic, we call its original constructor.
            this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        }
    });
}



function ok_http_ssl_cert_bypass() {
    setTimeout(function () {

        Java.perform(function () {

            var okhttp3_CertificatePinner_class = null;
            try {
                okhttp3_CertificatePinner_class = Java.use('okhttp3.CertificatePinner');
            } catch (err) {
                send('[-] OkHTTPv3 CertificatePinner class not found. Skipping.');
                okhttp3_CertificatePinner_class = null;
            }

            if (okhttp3_CertificatePinner_class != null) {

                try {
                    okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.util.List').implementation = function (str, list) {
                        send('[+] Bypassing OkHTTPv3 1: ' + str);
                        return true;
                    };
                    send('[+] Loaded OkHTTPv3 hook 1');
                } catch (err) {
                    send('[-] Skipping OkHTTPv3 hook 1');
                }

                try {
                    okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str, cert) {
                        send('[+] Bypassing OkHTTPv3 2: ' + str);
                        return true;
                    };
                    send('[+] Loaded OkHTTPv3 hook 2');
                } catch (err) {
                    send('[-] Skipping OkHTTPv3 hook 2');
                }

                try {
                    okhttp3_CertificatePinner_class.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (str, cert_array) {
                        send('[+] Bypassing OkHTTPv3 3: ' + str);
                        return true;
                    };
                    send('[+] Loaded OkHTTPv3 hook 3');
                } catch (err) {
                    send('[-] Skipping OkHTTPv3 hook 3');
                }

                try {
                    okhttp3_CertificatePinner_class['check$okhttp'].implementation = function (str, obj) {
                        send('[+] Bypassing OkHTTPv3 4 (4.2+): ' + str);
                    };
                    send('[+] Loaded OkHTTPv3 hook 4 (4.2+)');
                } catch (err) {
                    send('[-] Skipping OkHTTPv3 hook 4 (4.2+)');
                }

            }

        });

    }, 0);
}


var base64EncodeChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    base64DecodeChars = new Array((-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), 62, (-1), (-1), (-1), 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, (-1), (-1), (-1), (-1), (-1), (-1), (-1), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, (-1), (-1), (-1), (-1), (-1), (-1), 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, (-1), (-1), (-1), (-1), (-1));

function bytesToBase64(e) {
    var r, a, c, h, o, t;
    for (c = e.length, a = 0, r = ''; a < c;) {
        if (h = 255 & e[a++], a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4),
                r += '==';
            break
        }
        if (o = e[a++], a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
                r += base64EncodeChars.charAt((15 & o) << 2),
                r += '=';
            break
        }
        t = e[a++],
            r += base64EncodeChars.charAt(h >> 2),
            r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
            r += base64EncodeChars.charAt((15 & o) << 2 | (192 & t) >> 6),
            r += base64EncodeChars.charAt(63 & t)
    }
    return r
}

function hook_encryption_aes() {
    var secretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    secretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (a, b) {
        var result = this.$init(a, b);
        send("================= SecretKeySpec =====================");
        send("SecretKeySpec :: bytesToString :: " + bytesToString(a));
        send("SecretKeySpec :: bytesToBase64 :: " + bytesToBase64(a));
        send("SecretKeySpec :: bytesToHex :: " + bytesToHex(a));
        return result;
    }


    var ivParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    ivParameterSpec.$init.overload('[B').implementation = function (a) {
        var result = this.$init(a);
        send("\n================== IvParameterSpec ====================");
        send("IvParameterSpec :: bytesToString :: " + bytesToString(a));
        send("IvParameterSpec :: bytesToBase64 :: " + bytesToBase64(a));
        send("IvParameterSpec :: bytesToHex :: " + bytesToHex(a));
        return result;
    }
}

function hook_encryption_cipher() {
    var cipher = Java.use('javax.crypto.Cipher');
    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (a, b, c) {
        var result = this.init(a, b, c);
        send("\n================ cipher.init() ======================");

        if (a == '1') {
            send("init :: Encrypt Mode");
        } else if (a == '2') {
            send("init :: Decrypt Mode");
        }

        send("Mode :: " + a);
        return result;
    }
}

function hook_encryption_doFinal() {
    var cipher = Java.use('javax.crypto.Cipher');
    cipher.doFinal.overload("[B").implementation = function (x) {
        send("\n================ doFinal() ======================");
        var ret = cipher.doFinal.overload("[B").call(this, x);
        send("doFinal :: data to encrypt/decrypt - base64 :: " + bytesToBase64(x));
        send("doFinal :: data to encrypt/decrypt - string :: " + bytesToString(x));
        send("doFinal :: data to encrypt/decrypt - return value :: " + ret);
        send("doFinal :: data to encrypt/decrypt - return value :: " + String.fromCharCode.apply(String, ret));
        stackTrace();
        return ret;
    }
}

function bytesToString(arr) {
    var str = '';
    arr = new Uint8Array(arr);
    for (var i in arr) {
        str += String.fromCharCode(arr[i]);
    }
    return str;
}

function bytesToHex(arr) {
    var str = '';
    var k, j;
    for (var i = 0; i < arr.length; i++) {
        k = arr[i];
        j = k;
        if (k < 0) {
            j = k + 256;
        }
        if (j < 16) {
            str += "0";
        }
        str += j.toString(16);
    }
    return str;
}

function printHashMap(map) {
    Java.perform(function () {
        var HashMapNode = Java.use('java.util.HashMap$Node');
        var iterator = map.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = Java.cast(iterator.next(), HashMapNode);
            send("Key: " + entry.getKey() + ", Value: " + entry.getValue());
        }
    });
}

function UpdateHashMap(map, mapKey, newVal) {
    Java.perform(function () {
        var HashMapNode = Java.use('java.util.HashMap$Node');
        var iterator = map.entrySet().iterator();
        var jvar;
        if (typeof (newVal) == 'boolean') {
            jvar = Java.use('java.lang.Boolean').$new(newVal);
        }
        if (typeof (newVal) == 'string') {
            jvar = Java.use('java.lang.String').$new(newVal);
        }
        if (typeof (newVal) == 'number') {
            jvar = Java.use('java.lang.Integer').$new(newVal);
        }
        if (jvar != null) {
            var objVal = Java.cast(jvar, Java.use('java.lang.Object'));
            while (iterator.hasNext()) {
                var entry = Java.cast(iterator.next(), HashMapNode);
                var keyStr = entry.getKey().toString();
                if (keyStr.indexOf(mapKey) == 0) {
                    send("found key " + mapKey + " ,replacing value " + entry.getValue() + " with " + newVal);
                    entry.setValue(objVal);
                    send("updated value " + entry.getValue());
                }
            }
        }

    });
}

function printByteArr(bArr) {
    Java.perform(function () {
        var buffer = Java.array('byte', bArr);
        var result = "";
        for (var i = 0; i < buffer.length; ++i) {
            try {
                result += (String.fromCharCode(buffer[i]));
            } catch {
                send("failed adding bytes to string");
            }
        }
        send("Byte arr: \n" + result);
    });
}

function stackTrace() {
    var ThreadDef = Java.use('java.lang.Thread');
    var ThreadObj = ThreadDef.$new();
    var stack = ThreadObj.currentThread().getStackTrace();
    for (var i = 0; i < stack.length; i++) {
        send(i + " => " + stack[i].toString());
    }
}

function stackTrace2() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
}

function stringFromArray(data) {
    var count = data.length;
    var str = "";

    for (var index = 0; index < count; index += 1)
        str += String.fromCharCode(data[index]);

    return str;
}

function hook_webview_loadUrl(stackTraceIfContains) {
    Java.perform(function () {
        Java.use('android.webkit.WebView').loadUrl.overload('java.lang.String').implementation = function (str) {
            send("## Hooked loadUrl, str: " + str);
            // this.setWebContentsDebuggingEnabled(true);
            // send("[+]Setting the value of setWebContentsDebuggingEnabled() to TRUE");
            if (str != null && str.indexOf(stackTraceIfContains) != -1) {
                stackTrace();
            }
            return this.loadUrl(str);
        }
    });
}

function hook_webview_loadUrl_2(stackTraceIfContains) {
    Java.perform(function () {
        var WebView = Java.use('android.webkit.WebView');
        // Hook the overload that takes a String and a Map<String, String>
        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, headers) {
            send("## Hooked loadUrl2,  url: " + url + ", Headers: " + printHashMap(headers));
            if (url != null && url.indexOf(stackTraceIfContains) !== -1) {
                // If you have a stackTrace function implemented, call it here
                stackTrace();
            }
            // Proceed with the original call
            return this.loadUrl(url, headers);
        };
    });
}

function hook_URL_openConnection(stackTraceIfContains) {
    Java.perform(function () {
        Java.use('java.net.URL').openConnection.overload().implementation = function () {
            var url = this.toString();
            send("Hooked URL openConnection ,url: " + url);
            if (url.indexOf(stackTraceIfContains) != -1) {
                stackTrace();
            }
            return this.openConnection();
        }
    });
}

function hook_URL_new(stackTraceIfContains) {
    Java.perform(function () {
        Java.use('java.net.URL').$init.overload('java.lang.String').implementation = function (str) {
            send("Hooked URL_new ,url: " + str);
            if (str.indexOf(stackTraceIfContains) != -1) {
                stackTrace();
            }
            return this.$init(str);
        }
    });
}

function hook_fileDelete() {
    Java.perform(function () {
        Java.use('java.io.File').delete.overload().implementation = function () {
            var path = this.toString();
            send("Hooked File delete ,File: " + path);
            if (path.indexOf('') != -1) {
                return true;
            }
            return this.delete();
        }
    });
}

function hook_system_loadLibrary() {
    Java.perform(function () {
        const System = Java.use('java.lang.System');
        const Runtime = Java.use('java.lang.Runtime');
        const SystemLoad_2 = System.loadLibrary.overload('java.lang.String');
        const VMStack = Java.use('dalvik.system.VMStack');

        SystemLoad_2.implementation = function (library) {
            send("Loading dynamic library => " + library);
            try {
                const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
                if (library === 'myLib') {
                    //do my stuff
                }
                return loaded;
            } catch (ex) {
                console.log(ex);
            }
        };
    });
}

function hook_system_load() {
    Java.perform(function () {
        Java.use('java.lang.System').load.overload('java.lang.String').implementation = function (str) {
            send("Hooked system_load ,str: " + str);
            stackTrace();
            this.load(str);
        }
    });
}

function hook_assetManager_open() {
    Java.perform(function () {
        Java.use('android.content.res.AssetManager').open.overload('java.lang.String').implementation = function (filename) {
            send("Hooked assetManager_open ,fileName: " + filename);
            stackTrace2();
            return this.open(filename);
        }
    });
}

function hook_base64_decode(isTrace) {
    Java.perform(function () {
        var base64Cls = Java.use('android.util.Base64');
        base64Cls.decode.overload('[B', 'int').implementation = function (bArr, flag) {
            var output = this.decode(bArr, flag);
            send("Hooked base64_decode ,output: " + String.fromCharCode.apply(null, output));
            if (isTrace) {
                stackTrace2();
            }
            return output;
        }

        base64Cls.decode.overload('java.lang.String', 'int').implementation = function (str, flag) {
            // if (str.indexOf("x86") != -1 || str.indexOf("arm") != -1) {
            //     send("got some: " + str);
            //     return this.decode("d293", flag);
            // }
            var output = this.decode(str, flag);
            send("Hooked base64_decode ,input: " + str + " ,output: " + bytesToString(output));
            if (isTrace) {
                stackTrace2();
            }
            return output;
        }
    });
}

function hook_java_base64_encodeToString(isTrace) {
    Java.perform(function () {
        var base64Cls = Java.use('java.util.Base64$Encoder');
        base64Cls.encodeToString.overload('[B').implementation = function (bArr) {
            var output = this.encodeToString(bArr);
            send("Hooked hook_base64_encodeToString ,input: " + bytesToString(bArr) + ", output: " + output);
            if (isTrace) {
                stackTrace2();
            }
            return output;
        }
    });
}

function hook_telephonyManager_getSimOperator(mccMnc, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getSimOperator.overload().implementation = function () {
            let val = this.getSimOperator();
            send("Hooked telephonyManager_getSimOperator, value: " + val);
            if (isStackTrace) {
                stackTrace2();
            }
            if (mccMnc == '' || mccMnc == null) {
                val;
            }
            return mccMnc;
        }
    });
}

function hook_telephonyManager_getNwOperator(mccMnc, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getNetworkOperator.overload().implementation = function () {
            let val = this.getNetworkOperator()
            send("Hooked telephonyManager_getNetworkOperator, value: " + val);
            if (isStackTrace) {
                stackTrace2();
            }
            if (mccMnc == '' || mccMnc == null) {
                return val;
            }
            return mccMnc;
        }
    });
}

function hook_telephonyManager_getNetworkCountryIso1(countryShortName, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getNetworkCountryIso.overload().implementation = function () {
            if (isStackTrace) {
                stackTrace2();
            }
            let origCountry = this.getNetworkCountryIso();
            send("Hooked telephonyManager_getNetworkCountryIso1, Country to return: " + countryShortName);
            if (countryShortName == '' || countryShortName == null) {
                return origCountry;
            }
            return countryShortName;
        }
    });
}

function hook_telephonyManager_getNetworkCountryIso2(countryShortName, isStackTrace) {
    Java.perform(function () {
        try {
            Java.use('android.telephony.TelephonyManager').getNetworkCountryIso.overload('int').implementation = function (slotIndex) {
                send("Hooked telephonyManager_getNetworkCountryIso2, Slot Index: " + slotIndex);
                if (isStackTrace) {
                    stackTrace2();
                }
                if (countryShortName == '' || countryShortName == null) {
                    return this.getNetworkCountryIso();
                }
                return countryShortName;
            }
        }
        catch { }
    });
}

function hook_TelephonyManager_getSubsriberID1(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getSubscriberId.overload().implementation = function () {
            var res = this.getSubscriberId();
            send("Hooked TelephonyManager_getSubsriberID1 ,Res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            return res;
        }
    });
}

function hook_TelephonyManager_getSubsriberID2(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getSubscriberId.overload('int').implementation = function (num) {
            var res = this.getSubscriberId(num);
            send("Hooked TelephonyManager_getSubsriberID2 ,Int: " + num + ", Res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            return res;
        }
    });
}

function hook_TelephonyManager_getDeviceId1(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getDeviceId.overload().implementation = function () {
            var res = this.getDeviceId();
            send("Hooked TelephonyManager_getDeviceId1 ,Res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            return res;
        }
    });
}

function hook_TelephonyManager_getDeviceId2(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getDeviceId.overload('int').implementation = function (num) {
            var res = this.getDeviceId(num);
            send("Hooked TelephonyManager_getDeviceId2 ,Res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            return res;
        }
    });
}

function hook_telephonyManager_getSimOperatorName(operatorName, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getSimOperatorName.overload().implementation = function () {
            var res = this.getSimOperatorName();
            send("Hooked telephonyManager_getSimOperatorName, res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            if (operatorName == '' || operatorName == null) {
                return res;
            }
            return operatorName;
        }
    });
}

function hook_telephonyManager_getNetworkOperatorName(operatorName, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getNetworkOperatorName.overload().implementation = function () {
            var res = this.getNetworkOperatorName();
            send("Hooked telephonyManager_getNetworkOperatorName, res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            if (operatorName == '' || operatorName == null) {
                return res;
            }
            return operatorName;
        }
    });
}

function hook_telephonyManager_getSimCountryIso(simCountryIso, isStackTrace) {
    Java.perform(function () {
        try {
            Java.use('android.telephony.TelephonyManager').getSimCountryIso.overload().implementation = function () {
                var res = this.getSimCountryIso();
                send("Hooked telephonyManager_getSimCountryIso, res: " + res + ", ToReturn: " + simCountryIso);
                if (isStackTrace) {
                    stackTrace2();
                }
                return simCountryIso;
            }
        }
        catch { }
    });
}

function hook_telephonyManager_getSimState(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getSimState.overload().implementation = function () {
            var res = this.getSimState();
            send("Hooked telephonyManager_getSimState, default: " + res + ", ToReturn: " + 5);
            if (isStackTrace) {
                stackTrace2();
            }
            return 5;
        }
    });
}

function hook_telephonyManager_isNetworkRoaming(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').isNetworkRoaming.overload().implementation = function () {
            var res = this.isNetworkRoaming();
            send("Hooked telephonyManager_isNetworkRoaming, default: " + res + ", ToReturn: " + true);
            if (isStackTrace) {
                stackTrace2();
            }
            return true;
        }
    });
}

function hook_native_file_open() {
    Interceptor.attach(Module.findExportByName("libc.so", "open"), {
        onEnter: function (args) {
            this.flag = false;
            var filename = Memory.readCString(ptr(args[0]));
            if (filename.endsWith("meminfo") || filename.endsWith(".apk") || filename.endsWith(".so") || filename.endsWith(".dex") || filename.endsWith(".jar") || filename.indexOf("secondary-dexes") !== -1) {
                send('filename =' + filename)
                this.flag = true;
            }
        },
        onLeave: function (retval) {
            // if (this.flag) {
            //     send("Originl retval: " + retval);
            //     var newPath = "/data/data/com.re.reversershomeassignment/maps";
            //     var libcOpen = new NativeFunction(Module.findExportByName("libc.so", "open"), 'int', ['pointer', 'int']);
            //     var newPathPtr = Memory.allocUtf8String(newPath);
            //     var newFd = libcOpen(newPathPtr, 0);  // 0 is the default mode (O_RDONLY)
            //     send("New path: " + newPath);
            //     retval.replace(newFd);
            // }
        }
    });
}

function hook_native_file_dlopen() {
    Interceptor.attach(Module.findExportByName("libc.so", "dlopen"), {
        onEnter: function (args) {
            this.flag = false;
            var filename = Memory.readCString(ptr(args[0]));
            // send('dlopen - filename =' + filename)
            this.flag = true;
            var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
            send("dlopen - file name [ " + Memory.readCString(ptr(args[0])) + " ]\nBacktrace:" + backtrace);
        },
        onLeave: function (retval) {
            if (this.flag) // passed from onEnter
                send("\nopen retval: " + retval);
        }
    });
}

const su_binaries = [
    "/su",
    "/su/bin/su",
    "/system/bin/androVM_setprop",
    "/sbin/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/data/local/su",
    "/system/xbin/su",
    "/system/bin/su",
    "/system/bin/failsafe/su",
    "/system/bin/cufsdosck",
    "/system/xbin/cufsdosck",
    "/system/bin/cufsmgr",
    "/system/xbin/cufsmgr",
    "/system/bin/cufaevdd",
    "/system/xbin/cufaevdd",
    "/system/bin/conbb",
    "/system/xbin/conbb",
    "/data/adb/magisk",
    "/data/adb/modules",
    "/data/app/com.topjohnwu.magisk",
    "/data/data/com.topjohnwu.magisk",
    "/data/user_de/0/com.topjohnwu.magisk",
    "/config/sdcardfs/com.topjohnwu.magisk",
    "/data/data/com.topjohnwu.magisk",
    "/config/sdcardfs/com.topjohnwu.magisk",
    "/data/media/0/Android/data/com.topjohnwu.magisk",
    "/mnt/runtime/default/emulated/0/Android/data/com.topjohnwu.magisk"]

function hook_native_file_stat() {
    Interceptor.attach(Module.findExportByName("libc.so", "stat"), {
        onEnter: function (args) {
            this.flag = false;
            var inputFile = Memory.readCString(ptr(args[0]));
            if (su_binaries.includes(inputFile)) {
                this.flag = true;
                var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
                send("stat - " + inputFile + " ]\nBacktrace:" + backtrace);
            }
        },
        onLeave: function (retval) {
            if (this.flag) // passed from onEnter
                send("\netval: " + retval + " update response to -1");
            retval.replace(-1);
        }
    });
}

function hook_native_strstr() {
    Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
        onEnter: function (args) {
            this.flag = false;
            var haystack = Memory.readCString((args[0]));
            var needle = Memory.readCString((args[1]));
            this.flag = true;
            var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
            send("strstr - " + haystack + " " + needle + " ]\nBacktrace:" + backtrace);
        },
        onLeave: function (retval) {
            if (this.flag) // passed from onEnter
                send("\netval: " + retval);
        }
    });
}

function hook_fileDelete_native() {
    Interceptor.attach(Module.findExportByName("libc.so", "unlink"), {
        onEnter: function (args) {
            this.flag = false;
            var filename = Memory.readCString(ptr(args[0]));
            if (filename.endsWith(".dex") || filename.endsWith(".jar") || filename.indexOf("secondary-dexes") !== -1) {
                send('Delete file, filename =' + filename)
                this.flag = true;
                var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
                send("file name [ " + Memory.readCString(ptr(args[0])) + " ]\nBacktrace:" + backtrace);
            }
        },
        onLeave: function (retval) {
            if (this.flag) // passed from onEnter
                send("\nretval: " + retval);
        }
    });
}

function hook_WebChromeClient_shouldOverrideUrlLoading() {
    Java.perform(function () {
        Java.use('android.webkit.WebViewClient').shouldOverrideUrlLoading.overload('android.webkit.WebView', 'java.lang.String').implementation = function (webView, str) {
            send("Hooked WebChromeClient_shouldOverrideUrlLoading, Str: " + str);
            // stackTrace();
            return this.shouldOverrideUrlLoading(webView, str);
        }
    });
}

function hook_webview_addJavascriptInterface() {
    Java.perform(function () {
        Java.use('android.webkit.WebView').addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').implementation = function (obj, str) {
            send("Hooked webview_addJavascriptInterface ,obj Class: " + obj.getClass().getName() + ", str: " + str);
            // stackTrace();
            return this.addJavascriptInterface(obj, str);
        }
    });
}

function hook_webview_evaluateJavascript() {
    Java.perform(function () {
        Java.use('android.webkit.WebView').evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback').implementation = function (str, valCallback) {
            send("Hooked webview_evaluateJavascript ,str: " + str);
            stackTrace();
            return this.evaluateJavascript(str, valCallback);
        }
    });
}

function hook_webSettings_setJavaScriptEnabled() {
    Java.perform(function () {
        Java.use('android.webkit.WebSettings').setJavaScriptEnabled.implementation = function (bool) {
            send("Hooked webSettings_setJavaScriptEnabled ,bool: " + bool);
            // stackTrace();
            return this.setJavaScriptEnabled(bool);
        }
    });
}

function hook_webSettings_getUserAgentString() {
    Java.perform(function () {
        Java.use('android.webkit.WebSettings').getUserAgentString.implementation = function () {
            var userAgent = this.getUserAgentString();
            send("Hooked webSettings_getUserAgentString ,userAgent: " + userAgent);
            // stackTrace();
            return userAgent;
        }
    });
}

function hook_webSettings_setUserAgentString() {
    Java.perform(function () {
        Java.use('android.webkit.WebSettings').setUserAgentString.implementation = function (ua) {
            send("Hooked webSettings_setUserAgentString ,userAgent: " + ua);
            // stackTrace();
            return this.setUserAgentString(ua);
        }
    });
}

function process_killer() {
    Java.perform(function () {
        var procClass = Java.use('android.os.Process');
        var myPid = procClass.myPid();
        procClass.killProcess(myPid);
    });
}

function hook_Activity_onCreate() {
    Java.perform(function () {
        Java.use('android.app.Activity').onCreate.overload('android.os.Bundle').implementation = function (bundle) {
            send("#%#% Hooked Activity_onCreate, name: " + this.toString());
            return this.onCreate(bundle);
        }
    });
}

function hook_Activity_startActivity_1() {
    Java.perform(function () {
        Java.use('android.app.Activity').startActivity.overload('android.content.Intent').implementation = function (intent) {
            send("#%#% Hooked Activity_startActivity_1, Intent: " + intent);
            stackTrace();
            return this.startActivity(intent);
        }
    });
}

function hook_Activity_startActivity_2() {
    Java.perform(function () {
        Java.use('android.app.Activity').startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function (intent, bundle) {
            send("#%#% Hooked Activity_startActivity_2, Intent: " + intent + ", Bundle: " + bundle);
            stackTrace();
            return this.startActivity(intent, bundle);
        }
    });
}

function hook_Context_startActivity_1() {
    Java.perform(function () {
        Java.use('android.content.Context').startActivity.overload('android.content.Intent').implementation = function (intent) {
            send("#%#% Hooked Context_startActivity, Intent: " + intent);
            stackTrace();
            return this.startActivity(intent);
        }
    });
}

function hook_Context_startActivity_2() {
    Java.perform(function () {
        Java.use('android.content.Context').startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function (intent, bundle) {
            send("#%#% Hooked Context_startActivity_2, Intent: " + intent + ", Bundle: " + bundle);
            stackTrace();
            return this.startActivity(intent, bundle);
        }
    });
}

function hook_System_exit() {
    Java.perform(function () {
        Java.use('java.lang.System').exit.implementation = function (int) {
            send("Hooked System_exit, int: " + int);
            stackTrace();
            return;
            // return this.exit(int);
        }
    });
}

function hook_AdvertisingIdClient_Info_getId() {
    Java.perform(function () {
        Java.use('com.google.android.gms.ads.identifier.AdvertisingIdClient$Info').getId.implementation = function () {
            var res = this.getId();
            send("Hooked AdvertisingIdClient_Info_getId, ad id: " + res);
            stackTrace();
            return res;
        }
    });
}

function hook_packageManager_queryIntentActivities() {
    Java.perform(function () {
        Java.use('android.content.pm.PackageManager').queryIntentActivities.overload('android.content.Intent', 'int').implementation = function (intent, flag) {
            var res = this.queryIntentActivities(intent, flag);
            send("Hooked packageManager_queryIntentActivities, intent: " + intent + ", Flag: " + flag + ", List length: " + res.size());
            stackTrace();
            return res;
        }
    });
}

function hook_hashMap_put() {
    Java.perform(function () {
        Java.use('java.util.HashMap').put.implementation = function (key, val) {
            send("Hooked hashMap_put, key: " + key + ", Val: " + val);
            return this.put(key, val);
        }
    });
}

function hook_Location_getLatitude() {
    Java.perform(function () {
        Java.use('android.location.Location').getLatitude.overload().implementation = function () {
            var res = this.getLatitude();
            send("Hooked Location_getLatitude, res: " + res);
            stackTrace();
            return res;
        }
    });
}

function hook_Location_getLongitude() {
    Java.perform(function () {
        Java.use('android.location.Location').getLongitude.overload().implementation = function () {
            var res = this.getLongitude();
            send("Hooked Location_getLongitude, res: " + res);
            stackTrace();
            return res;
        }
    });
}

function hook_VpnService_Builder_addAllowedApplication() {
    Java.perform(function () {
        Java.use('android.net.VpnService$Builder').addAllowedApplication.implementation = function (packageName) {
            send("Hooked VpnService_Builder_addAllowedApplication, package: " + packageName);
            this.addAllowedApplication("buhaha.scary.webview1");
            stackTrace();
            return this.addAllowedApplication(packageName);
        }
    });
}

function printArrOfObjects(oArr) {
    Java.perform(function () {
        var arraysClass = Java.use("java.util.Arrays");
        console.log("Arr Elements: " + arraysClass.toString(oArr));
    });
}

function hook_VpnService_prepare() {
    Java.perform(function () {
        Java.use('android.net.VpnService').prepare.implementation = function (ctx) {
            send("Hooked VpnService_prepare");
            stackTrace();
            return this.prepare(ctx);
        }
    });
}

function hook_NetworkCapabilities_vpnUsage() {
    Java.perform(function () {
        Java.use('android.net.NetworkCapabilities').hasTransport.implementation = function (transportType) {
            if (transportType == 4) {
                return false;
            }
            else {
                return this.hasTransport(transportType);
            }
        }
    });
}

function hook_fileOutputStream_init() {
    Java.perform(function () {
        Java.use('java.io.FileOutputStream').$init.overload('java.io.File').implementation = function (file) {
            console.log("Hooked fileOutputStream_init ,fileName: " + file.toString());
            stackTrace();
            return this.$init(file);
        }
    });
}

function hook_File_createNewFile() {
    Java.perform(function () {
        Java.use('java.io.File').createNewFile.implementation = function () {
            var path = this.getPath();
            // if (path.indexOf('dex') != -1 || path.indexOf('tmp') != -1 || path.indexOf('jar') != -1 || path.indexOf('dex') != -1) {
            console.log("Hooked File_createNewFile, path: " + path);
            stackTrace();
            // }
            return this.createNewFile();
        }
    });
}

function generateRandomAndroidId() {
    const hexChars = "0123456789abcdef";
    let androidId = "";
    for (let i = 0; i < 16; i++) {
        const randomIndex = Math.floor(Math.random() * hexChars.length);
        androidId += hexChars[randomIndex];
    }
    return androidId;
}


const sysVarsRes = { 'adb_enabled': "0", 'development_settings_enabled': "0", "android_id": "e4d98c34c25432f3" };
//const sysVarsRes = { 'adb_enabled': "0", };

function SysPropsBypass(isStackTrace) {
    var Secure = Java.use('android.provider.Settings$Secure');
    var System = Java.use('android.provider.Settings$System');
    var Global = Java.use('android.provider.Settings$Global');

    Secure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, str, int) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str, int);
        }
    }
    Secure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str);
        }
    }
    System.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, str, int) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str, int);
        }
    }
    System.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str);
        }
    }
    Global.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, str, int) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str, int);
        }
    }
    Global.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str);
        }
    }

    Secure.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function (cr, str, fl) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str, fl);
        }
    }
    Secure.getFloat.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str);
        }
    }
    System.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function (cr, str, fl) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str, fl);
        }
    }
    System.getFloat.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str);
        }
    }
    Global.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function (cr, str, fl) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str, fl);
        }
    }
    Global.getFloat.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str);
        }
    }

    Secure.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function (cr, str, lng) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str, lng);
        }
    }
    Secure.getLong.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str);
        }
    }
    System.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function (cr, str, lng) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str, lng);
        }
    }
    System.getLong.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str);
        }
    }
    Global.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function (cr, str, lng) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str, lng);
        }
    }
    Global.getLong.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str);
        }
    }

    Secure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getString(cr, str);
        }
    }
    System.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getString(cr, str);
        }
    }
    Global.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getString(cr, str);
        }
    }

    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
        console.warn('[*] Debug.isDebuggerConnected() Bypass !');
        return false;
    }
}

function antiFridaBypass() {
    Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {

        onEnter: function (args) {

            this.haystack = args[0];
            this.needle = args[1];
            this.frida = Boolean(0);

            haystack = Memory.readUtf8String(this.haystack);
            needle = Memory.readUtf8String(this.needle);

            if (haystack.indexOf("frida") !== -1 || haystack.indexOf("xposed") !== -1) {
                this.frida = Boolean(1);
            }
        },

        onLeave: function (retval) {

            if (this.frida) {
                retval.replace(0);
            }
            return retval;
        }
    });
}

function flock_hook(isTrace) {
    Interceptor.attach(Module.findExportByName("libc.so", "flock"), {

        onEnter: function (args) {
            console.log("flock onEnter, pid: " + Process.id);
            if (isTrace) {
                send('flock_hook called from:\n' +
                    Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
            }
        },

        onLeave: function (retval) {
            console.log("flock onLeave");
            return retval;
        }
    });
}

function fork_hook(isTrace) {
    Interceptor.attach(Module.findExportByName("libc.so", "fork"), {

        onEnter: function (args) {
            console.log("flock onEnter, pid: " + Process.id + ", file Descriptor: " + args[0].toInt32());
            if (isTrace) {
                send('flock_hook called from:\n' +
                    Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
            }
        },

        onLeave: function (retval) {
            console.log("fork onLeave");
            return retval;
        }
    });
}

function hook_getCookie() {
    const cookieManager = 'android.webkit.CookieManager';
    const cookieManagerCls = Java.use(cookieManager);
    cookieManagerCls.getInstance.overload().implementation = function () {
        const instance = this.getInstance();
        const cls = instance.getClass();
        const dynamicGeneratedCls = Java.ClassFactory.get(cls.getClassLoader()).use(cls.getName());
        dynamicGeneratedCls.getCookie.overload('java.lang.String').implementation = function (url) {
            const cookie = Java.cast(this, cookieManagerCls).getCookie(url);
            console.log("getCookie Hooked. URL: " + url + ". Cookie: " + cookie);
            return cookie;
        }
        return instance;
    }
}

function cellularHooks(isTrace) {
    // SIM Info
    // var mMccMnc = "40433";
    // var mShortCountryName = "in";
    // var mMccMnc = "310260";
    // var mShortCountryName = "us";
    // var mMccMnc = "43102";
    // var mShortCountryName = "ae";
    // var mMccMnc = "43220";
    // var mShortCountryName = "ir";
    // var mMccMnc = "42007"; // Zain
    // var operatorName = "Zain"
    // var mShortCountryName = "sa";
    // var mMccMnc = "25505";
    // var mShortCountryName = "ua";
    // var mMccMnc = "46007";
    // var mShortCountryName = "cn";
    // var mMccMnc = "23436";
    // var mShortCountryName = "gb";
    //---------------------------------
    // var mMccMnc = "45201";
    // var operatorName = "MobiFone";
    // var mShortCountryName = "vn";
    //---------------------------------
    // var mMccMnc = "20825";
    // var operatorName = "Lycamobile";
    // var mShortCountryName = "fr";
    //---------------------------------
    // var mMccMnc = "25034";
    // var operatorName = "Krymtelecom";
    // var mShortCountryName = "ru";
    //---------------------------------
    // var mMccMnc = "45411";
    // var operatorName = "China-Hong Kong Telecom";
    // var mShortCountryName = "hk";
    //---------------------------------
    // var mMccMnc = "22610";
    // var operatorName = "Orange";
    // var mShortCountryName = "ro";
    //---------------------------------
    // var mMccMnc = "52005"; // dtac TriNet / LINE
    // var operatorName = "DTAC";
    // var mShortCountryName = "th";
    //---------------------------------
    var mMccMnc = "52018"; // DTAC
    var operatorName = "DTAC";
    var mShortCountryName = "th";
    //---------------------------------
    // var mMccMnc = "52003"; // AIS/Advanced Info Service
    // var operatorName = "AIS";
    // var mShortCountryName = "th";
    //---------------------------------
    // var mMccMnc = "50216"; // Digi Telecommunications
    // var operatorName = "digi";
    // var mShortCountryName = "my";
    //---------------------------------
    // var mMccMnc = "50219"; // CelCom
    // var operatorName = "Celcom";
    // var mShortCountryName = "my";
    //---------------------------------
    // var mMccMnc = "23002"; // O2
    // var operatorName = "O2";
    // var mShortCountryName = "cz";
    //---------------------------------
    // var mMccMnc = "23402"; // O2
    // var operatorName = "O2";
    // var mShortCountryName = "gb";
    //---------------------------------
    // var mMccMnc = "42404";
    // var mShortCountryName = "ae";
    // var operatorName = "Etisalat"
    // ---------------------------------
    // var mMccMnc = "42403";
    // var mShortCountryName = "ae";
    // var operatorName = "DU"
    //---------------------------------
    // var mMccMnc = "334010"; // AT&T
    // var operatorName = "att";
    // var mShortCountryName = "mx";
    //---------------------------------
    // var mMccMnc = "22206"; // Vodafone
    // var operatorName = "vodafone";
    // var mShortCountryName = "it";
    //---------------------------------
    // var mMccMnc = "724299";
    // var operatorName = "Cinco";
    // var mShortCountryName = "br";
    //---------------------------------
    // var mMccMnc = "42508"; // Golan Telecom
    // var operatorName = "Golan";
    // var mShortCountryName = "il";
    //---------------------------------
    // var mMccMnc = "25099";
    // var operatorName = "Beeline";
    // var mShortCountryName = "ru";
    //---------------------------------
    // var mMccMnc = "28601";
    // var operatorName = "Turkcell";
    // var mShortCountryName = "tr";
    //---------------------------------
    // var mMccMnc = "41003";
    // var operatorName = "Ufone";
    // var mShortCountryName = "pk";
    //---------------------------------
    // var mMccMnc = "40433";
    // var operatorName = "Aircel";
    // var mShortCountryName = "in";
    //---------------------------------
    // var mMccMnc = "312210";
    // var operatorName = "AT&T Mobility";
    // var mShortCountryName = "us";
    //---------------------------------
    // var mMccMnc = "25501";
    // var operatorName = "Vodafone";
    // var mShortCountryName = "ua";

    var isStackTrace = isTrace;
    hook_telephonyManager_getSimState(isTrace);
    hook_telephonyManager_isNetworkRoaming(isTrace);

    hook_telephonyManager_getSimCountryIso(mShortCountryName, isStackTrace);
    hook_telephonyManager_getSimOperator(mMccMnc, isStackTrace);
    hook_telephonyManager_getNwOperator(mMccMnc, isStackTrace);
    hook_telephonyManager_getNetworkCountryIso1(mShortCountryName, isStackTrace);
    hook_telephonyManager_getNetworkCountryIso2(mShortCountryName, isStackTrace);

    hook_TelephonyManager_getSubsriberID1(isStackTrace);
    hook_TelephonyManager_getSubsriberID2(isStackTrace);
    hook_TelephonyManager_getDeviceId1(isStackTrace);
    hook_TelephonyManager_getDeviceId2(isStackTrace);

    hook_telephonyManager_getSimOperatorName(operatorName, isStackTrace);
    hook_telephonyManager_getNetworkOperatorName(operatorName, isStackTrace);
}

function hook_InputMethodSubtype_getLanguageTag(retVal) {
    Java.perform(function () {
        Java.use('android.view.inputmethod.InputMethodSubtype').getLanguageTag.implementation = function () {
            let locale = this.getLanguageTag();
            send('Hooked InputMethodSubtype getLanguageTag, value: ' + locale);
            if (retVal != null && retVal.length > 0) {
                return retVal;
            }
            return this.getLanguageTag();
        }
    });
}

function hook_TimeZone_getDefault(retVal) {
    Java.perform(function () {
        let tz = Java.use('android.icu.util.TimeZone');
        tz.getDefault.implementation = function () {
            let tz = this.getDefault();
            send('Hooked android.icu.util.TimeZone_getDefault, value: ' + tz.getID());
            if (retVal != null && retVal.length > 0) {
                return tz.getTimeZone(retVal);
            }
            stackTrace();
            return tz;
        }
    });
}

function hook_TimeZone2_getDefault(retVal) {
    Java.perform(function () {
        let tz = Java.use('java.util.TimeZone');
        tz.getDefault.implementation = function () {
            let tz = this.getDefault();
            send('Hooked java.util.TimeZone_getDefault, value: ' + tz.getID());
            if (retVal != null && retVal.length > 0) {
                return tz.getTimeZone(retVal);
            }
            stackTrace();
            return tz;
        }
    });
}

function hook_account_init() {
    Java.perform(function () {
        Java.use('android.accounts.Account').$init.overload('java.lang.String', 'java.lang.String').implementation = function (name, type) {
            send('Hooked account_init, name: ' + name + ' , type: ' + type);
            return this.$init(name, type);
        }
    });
}

function hook_AccountManager_addAccountExplicitly() {
    Java.perform(function () {
        let addAcountEx = Java.use('android.accounts.AccountManager').addAccountExplicitly.overload('android.accounts.Account', 'java.lang.String', 'android.os.Bundle');
        addAcountEx.implementation = function (account, pass, userData) {
            let ps = '';
            if (pass != null) {
                ps = pass;
            }
            send('Hooked AccountManager_addAccountExplicitly, account: ' + account.toString() + ' , pass: ' + ps + ', bundle: ' + userData);
            return this.addAccountExplicitly(account, pass, userData);
        }
    });
}

function hook_ContentResolver_isSyncPending() {
    Java.perform(function () {
        let isSyncPen = Java.use('android.content.ContentResolver').isSyncPending;
        isSyncPen.implementation = function (account, authority, extras) {
            let res = this.isSyncPending(account, authority);
            send('Hooked ContentResolver_isSyncPending, account: ' + account + ' , authority: ' + authority + ', res: ' + res);
            return res;
        }
    });
}

function hook_ContentResolver_requestSync() {
    Java.perform(function () {
        let reqSync = Java.use('android.content.ContentResolver').requestSync.overload('android.accounts.Account', 'java.lang.String', 'android.os.Bundle');
        reqSync.implementation = function (account, authority, extras) {
            send('Hooked ContentResolver_requestSync, account: ' + account + ' , authority: ' + authority + ' , extras: ' + extras);
            return this.requestSync(account, authority, extras);
        }
    });
}

function hook_ContentResolver_addPeriodicSync() {
    Java.perform(function () {
        Java.use('android.content.ContentResolver').addPeriodicSync.implementation = function (account, authority, extras, pollFreq) {
            send('Hooked ContentResolver_addPeriodicSync, account: ' + account + ' , authority: ' + authority + ' , extras: ' + extras + ' , pollFreq: ' + pollFreq);
            return this.addPeriodicSync(account, authority, extras, pollFreq);
        }
    });
}

function hook_BluetoothAdapter_getBondedDevices() {
    Java.perform(function () {
        Java.use('android.bluetooth.BluetoothAdapter').getBondedDevices.implementation = function () {
            let bondedDevices = this.getBondedDevices();
            send('Hooked BluetoothAdapter_getBondedDevices, size: ' + bondedDevices.size());
            let hashSet = Java.use('java.util.HashSet');
            let BTDev = Java.use('android.bluetooth.BluetoothDevice');
            let BTDevObj = BTDev.$new('00:11:22:33:EE:FF');
            let newBondedDevices = hashSet.$new();
            newBondedDevices.add(BTDevObj);
            return newBondedDevices;
        }
    });
}

function hook_PackageManager_getInstallerPackageName() {
    Java.perform(function () {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");

        PackageManager.getInstallerPackageName.overload("java.lang.String").implementation = function (packageName) {
            var returnVal = this.getInstallerPackageName(packageName);
            send("hook_PackageManager_getInstallerPackageName, package: " + packageName + ", return value: " + returnVal);
            var playInstallerPackage = "com.android.vending";
            send("Returning Play installer package: " + playInstallerPackage);
            return playInstallerPackage;
        };
    });
}

function traceClasses() {
    Java.perform(function () {
        // Java.enumerateLoadedClassesSync();
        // Trace all
        [
            // "com.re.reversershomeassignment.MainActivity"
            // "android.content.SharedPreferences$Editor",
            // "android.content.SharedPreferences",
            // "android.content.ContentValues",
            // "org.json.JSONObject",
            // "org.json.JSONArray",
            // "com.google.android.gms.location.FusedLocationProviderClient",

            // "com.tencent.mmkv.MMKV"

            // "com.reactnativecommunity.cookies.CookieManagerModule",
            // "com.reactnativecommunity.webview.RNCWebView",
            // "com.reactnativecommunity.cookies.CookieManagerModule",

            // "io.grpc.okhttp.OkHttpChannelBuilder$OkHttpTransportFactory",
            // "io.grpc.internal.InternalSubchannel",
            // "io.grpc.internal.ChannelLoggerImpl"

            // "android.util.Base64",

            // "android.os.SystemClock"

        ].forEach(traceClass);
    });
}

function hook_installTimeUpdate(hoursDiff) {
    Java.perform(function () {
        try {
            var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
            var sys = Java.use('java.lang.System');
            var timeDiff = 3600000 * hoursDiff;
            var pm = context.getPackageManager();
            var pn = context.getPackageName();
            var pi = pm.getPackageInfo(pn, 0);
            var newTime = sys.currentTimeMillis() - timeDiff;
            console.log("Update first install time " + hoursDiff + " hours back");
            pi.firstInstallTime.value = newTime;
        }
        catch { }
    });
}

function waitForDebugger() {
    Java.perform(function () {
        // var attachBasectx = Java.use('android.app.Application').attachBaseContext;
        var attachBasectx = Java.use('android.content.ContextWrapper').attachBaseContext;

        attachBasectx.implementation = function (ctx) {
            console.log("[+] Waiting for debugger to attach!");
            while (!Process.isDebuggerAttached()) {
            }
            console.log("[+] Debugger attached!");
            return this.attachBaseContext(ctx);
        }
    });
}

// Unity
function unity_printBridgeMsg() {
    let com_unity3d_player_UnityPlayer = Java.use('com.unity3d.player.UnityPlayer');
    com_unity3d_player_UnityPlayer.nativeUnitySendMessage.overload("java.lang.String", "java.lang.String", "[B").implementation = function (arg0, arg1, arg2) {
        console.log(`[+] Hooked com.unity3d.player.UnityPlayer.nativeUnitySendMessage: arg0=${arg0}, arg1=${arg1}, arg2=${String.fromCharCode.apply(String, arg2)}`);
        this['nativeUnitySendMessage'](arg0, arg1, arg2);
    };
}

function newUnityStr(input) {
    const il2cpp_string_new = new NativeFunction(
        Module.findExportByName('libil2cpp.so', 'il2cpp_string_new'),
        'pointer',
        ['pointer']
    );

    // Step 2: Create a new C string
    const newCString = Memory.allocUtf8String(input);

    // Step 3: Create a new System_String object
    const unityStr = il2cpp_string_new(newCString);

    return unityStr;
}

function unityToJSStr(unityStr) {
    if (!unityStr.isNull()) {
        const stringObject = unityStr;

        // IL2CPP header size and string length offset might differ based on the target architecture
        const headerSize = 0x10; // Assuming a common header size
        const lengthOffset = headerSize; // Length is right after the header
        const length = stringObject.add(lengthOffset).readInt(); // Read the length of the string

        if (length > 0) {
            // UTF-16 characters start right after the length field
            const utf16Chars = stringObject.add(lengthOffset + 4);
            const jsString = utf16Chars.readUtf16String(length);
            return jsString;
        } else {
            send('Returned string is empty');
        }
    } else {
        send('Returned string is null');
    }
    return '';
}

function unity_string_toLower() {
    send('Hooking unity_string_toLower');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xB9FD40');
    Interceptor.attach(offset, {
        onEnter(args) {
            send("unity_string_toLower Enter");
        },
        onLeave(retval) {
            let jstr = unityToJSStr(retval);
            send("unity_string_toLower Leave, response: " + jstr);
        }
    });
}


function UnityEngine_SystemInfo_GetDeviceModel() {
    send('Hooking unity_string_toLower');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xFACFF8');
    Interceptor.attach(offset, {
        onEnter(args) {
            send("UnityEngine_SystemInfo_GetDeviceModel Enter");
        },
        onLeave(retval) {
            let jstr = unityToJSStr(retval);
            send("UnityEngine_SystemInfo_GetDeviceModel Leave, response: " + jstr);
            if (jstr.indexOf('Google') > -1) {
                let toReplace = jstr.replace('Google', 'Boogle');
                send("unity_string_toLower Leave, replacing to: " + toReplace);
                let newVal = newUnityStr(toReplace);
                retval.replace(newVal);
            }
        }
    });
}

function unity_TimeZoneInfo_getDisplayName() {
    send('Hooking unity_TimeZoneInfo_getDisplayName');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xBA788C');
    Interceptor.attach(offset, {
        onEnter(args) {
            send("unity_TimeZoneInfo_getDisplayName Enter");
        },
        onLeave(retval) {
            let jstr = unityToJSStr(retval);
            send("unity_TimeZoneInfo_getDisplayName Leave, response: " + jstr);
            let newVal = newUnityStr('(GMT-01:00) Local Time');
            retval.replace(newVal);

        }
    });
}

function unity_String_Contains() {
    send('Hooking unity_String_Contains');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xBA037C');
    Interceptor.attach(offset, {
        onEnter(args) {
            var first = unityToJSStr(args[0]);
            var second = unityToJSStr(args[1]);
            send("unity_String_Contains Enter, first: " + first + ", second: " + second);

        },
        onLeave(retval) {
            if (retval.isNull()) {
                console.log('Returned boolean: null');
            } else {
                try {
                    // Assuming the return value is a boolean stored as a single byte
                    const nativeBool = retval.toUInt32() & 0xFF;  // Read the byte value
                    const jsBool = nativeBool !== 0;
                    console.log('unity_String_Contains - Returned boolean: ' + jsBool);
                } catch (e) {
                    console.log('Error reading returned boolean: ' + e);
                }
            }
        }
    });
}

function unity_TimeZoneInfo_getLocal() {
    send('Hooking unity_TimeZoneInfo_getLocal');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xBA488C');
    Interceptor.attach(offset, {
        onEnter(args) {
            send("unity_TimeZoneInfo_getLocal Enter");
        },
        onLeave(retval) {
            send("unity_TimeZoneInfo_getLocal Leave");
            if (!retval.isNull()) {
                const timeZoneInfo = retval;

                // Assuming header size for IL2CPP object is 0x10 (this can vary)
                const headerSize = 0x10;

                // Offsets of fields within TimeZoneInfo
                const idOffset = headerSize + 0x8; // Adjust based on actual structure
                const baseUtcOffsetOffset = headerSize + 0x10; // Adjust based on actual structure

                // Read the id field (System.String)
                const idPtr = timeZoneInfo.add(idOffset).readPointer();
                const idLengthOffset = 0x10; // Assuming string length is at 0x10 from the start of the string object
                const idLength = idPtr.add(idLengthOffset).readInt();
                const idChars = idPtr.add(idLengthOffset + 4); // Assuming UTF-16 chars start after the length field
                const id = idChars.readUtf16String(idLength);

                // Read the baseUtcOffset field (TimeSpan struct, assuming Ticks is at the start)
                const baseUtcOffsetTicks = timeZoneInfo.add(baseUtcOffsetOffset).readS64();

                console.log('TimeZoneInfo ID: ' + id);
                console.log('Base UTC Offset Ticks: ' + baseUtcOffsetTicks);
            } else {
                console.log('Returned TimeZoneInfo is null');
            }
        }
    });
}

function unityEngine_AndroidJavaObject_call() {
    send('Hooking UnityEngine_AndroidJavaObject__Call');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xF89658');
    Interceptor.attach(offset, {
        onEnter(args) {
            send("UnityEngine_AndroidJavaObject__Call Enter");
            const androidJavaObjectPtr = args[0];

            const jobjectPtrOffset = 0x18;
            const jobjectPointer = androidJavaObjectPtr.add(jobjectPtrOffset);
            let clsName = unityToJSStr(jobjectPointer);
            console.log('Class name:' + clsName);

            let methodName = unityToJSStr(args[1]);
            console.log('Method name:' + methodName);
        },
        onLeave(retval) {
            send("UnityEngine_AndroidJavaObject__Call Leave");
        }
    });
}

function waitForLibLoading(libraryName) {
    var isLibLoaded = false;
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            var libraryPath = Memory.readCString(args[0]);
            if (libraryPath.includes(libraryName)) {
                console.log("[+] Loading library " + libraryPath + "...");
                isLibLoaded = true;
            }
        },
        onLeave: function (args) {
            if (isLibLoaded) {
                isLibLoaded = false;
            }
        }
    });
}

function waitForLoad(libName) {
    var baseAdrr;
    var interv = setInterval(function () {
        baseAdrr = Module.findBaseAddress(libName);
        if (baseAdrr) {
            send('Loaded lib: ' + libName);
            clearInterval(interv);
            hookNativeMethods();
        }
    }, 10);
}

function hookNativeMethods() {
    // unity_string_toLower();
    // unity_TimeZoneInfo_getLocal();
    // unity_TimeZoneInfo_getDisplayName();
    // unity_String_Contains();
    // UnityEngine_SystemInfo_GetDeviceModel();
    unityEngine_AndroidJavaObject_call();
}

function printJSMap(map) {
    // Check if the input is a Map
    if (!(map instanceof Map)) {
        console.log("Input is not a Map.");
        return;
    }

    // Iterate over the map entries
    for (const [key, value] of map.entries()) {
        console.log(`${key}: ${value}`);
    }
}

function printJSObject(obj) {
    if (typeof obj !== 'object' || obj === null) {
        console.log("Input is not a valid object.");
        return;
    }

    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            console.log(`${key}: ${obj[key]}`);
        }
    }
}

function printCurrentBuildValues() {
    var buildCls = Java.use('android.os.Build');

    send("Current Build values:");
    send("BOARD: " + buildCls.BOARD.value);
    send("BOOTLOADER: " + buildCls.BOOTLOADER.value);
    send("BRAND: " + buildCls.BRAND.value);
    send("DEVICE: " + buildCls.DEVICE.value);
    send("DISPLAY: " + buildCls.DISPLAY.value);
    send("FINGERPRINT: " + buildCls.FINGERPRINT.value);
    send("HARDWARE: " + buildCls.HARDWARE.value);
    send("HOST: " + buildCls.HOST.value);
    send("ID: " + buildCls.ID.value);
    send("MANUFACTURER: " + buildCls.MANUFACTURER.value);
    send("MODEL: " + buildCls.MODEL.value);
    send("PRODUCT: " + buildCls.PRODUCT.value);
    send("TAGS: " + buildCls.TAGS.value);
    send("TYPE: " + buildCls.TYPE.value);
    send("USER: " + buildCls.USER.value);

    // SERIAL is deprecated in newer Android versions and may be inaccessible:
    // send("SERIAL: " + buildCls.SERIAL.value);
}

function updateBuildInfo(valuesMap) //printJSObject(valuesMap);
{

    printCurrentBuildValues();

    send("Updated Build values:")
    printJSObject(valuesMap);

    var buildCls = Java.use('android.os.Build');

    // Each field is static, so we assign to .value
    // Only assign if the key exists in the map to avoid overwriting with undefined
    if ('BOARD' in valuesMap) buildCls.BOARD.value = valuesMap['BOARD'];
    if ('BOOTLOADER' in valuesMap) buildCls.BOOTLOADER.value = valuesMap['BOOTLOADER'];
    if ('BRAND' in valuesMap) buildCls.BRAND.value = valuesMap['BRAND'];
    if ('DEVICE' in valuesMap) buildCls.DEVICE.value = valuesMap['DEVICE'];
    if ('DISPLAY' in valuesMap) buildCls.DISPLAY.value = valuesMap['DISPLAY'];
    if ('FINGERPRINT' in valuesMap) buildCls.FINGERPRINT.value = valuesMap['FINGERPRINT'];
    if ('HARDWARE' in valuesMap) buildCls.HARDWARE.value = valuesMap['HARDWARE'];
    if ('HOST' in valuesMap) buildCls.HOST.value = valuesMap['HOST'];
    if ('ID' in valuesMap) buildCls.ID.value = valuesMap['ID'];
    if ('MANUFACTURER' in valuesMap) buildCls.MANUFACTURER.value = valuesMap['MANUFACTURER'];
    if ('MODEL' in valuesMap) buildCls.MODEL.value = valuesMap['MODEL'];
    if ('PRODUCT' in valuesMap) buildCls.PRODUCT.value = valuesMap['PRODUCT'];
    if ('TAGS' in valuesMap) buildCls.TAGS.value = valuesMap['TAGS'];
    if ('TYPE' in valuesMap) buildCls.TYPE.value = valuesMap['TYPE'];
    if ('USER' in valuesMap) buildCls.USER.value = valuesMap['USER'];

    // Some fields like `SERIAL` or `TIME` may be device or API level dependent
    // Check the Android docs if you need to modify them. SERIAL often requires special handling.
    if ('SERIAL' in valuesMap) {
        // On modern Android versions, Build.SERIAL is deprecated and read-only.
        // Frida may still let you set it, but it won't necessarily reflect in the system.
        buildCls.SERIAL.value = valuesMap['SERIAL'];
    }
}

function getBuildProfile(profileName) {
    const pixel6 = {
        MANUFACTURER: 'Google',
        MODEL: 'Pixel 6',
        BRAND: 'google',
        DEVICE: 'oriole',
        PRODUCT: 'oriole',
        FINGERPRINT: 'google/oriole/oriole:12/SP2A.220305.013.A3/8229987:user/release-keys',
        HARDWARE: 'oriole',
        ID: 'SP2A.220305.013.A3',
        DISPLAY: 'SP2A.220305.013.A3',
        TYPE: 'user'
    };

    // Samsung Galaxy S22 (Example values; may not match exact released builds)
    const samsungS22 = {
        MANUFACTURER: 'Samsung',
        MODEL: 'SM-S901B',
        BRAND: 'samsung',
        DEVICE: 'r0',
        PRODUCT: 'r0xx',
        // Example fingerprint pattern; replace with actual known fingerprint if available
        FINGERPRINT: 'samsung/r0xx/r0:13/TP1A.220905.004/9999999:user/release-keys',
        HARDWARE: 'qcom',
        ID: 'TP1A.220905.004',
        DISPLAY: 'TP1A.220905.004',
        TYPE: 'user'
    };

    // OnePlus Nord 3 (Example values)
    const onePlusNord3 = {
        MANUFACTURER: 'OnePlus',
        MODEL: 'CPH2493',
        BRAND: 'OnePlus',
        DEVICE: 'CPH2493',
        PRODUCT: 'CPH2493EEA',
        // Example fingerprint pattern; replace with actual known fingerprint if available
        FINGERPRINT: 'OnePlus/CPH2493EEA/CPH2493:13/EB210210209/1234567:user/release-keys',
        HARDWARE: 'mt6894',
        ID: 'EB210210209',
        DISPLAY: 'EB210210209',
        TYPE: 'user'
    };

    const googleEmulator = {
        MANUFACTURER: 'Google',
        MODEL: 'sdk_gphone64_x86_64',
        BRAND: 'google',
        DEVICE: 'emulator64_x86_64_arm64',
        PRODUCT: 'sdk_gphone64_x86_64',
        FINGERPRINT: 'google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys',
        HARDWARE: 'ranchu',
        ID: 'SE1B.220616.007',
        DISPLAY: 'sdk_gphone64_x86_64-userdebug 12 SE1B.220616.007 10056955 dev-keys',
        TYPE: 'userdebug'
    };

    const profilesMap = {
        "pixel6": pixel6,
        "samsungS22": samsungS22,
        "onePlusNord3": onePlusNord3,
        "androidStudioEmulator": googleEmulator,
    };

    return profilesMap[profileName] || null;
}

function hook_firestore_DocumentSnapshot_get(keyStr, newVal) {
    Java.perform(function () {
        Java.use('com.google.firebase.firestore.DocumentSnapshot').get.overload('java.lang.String').implementation = function (key) {
            var resObj = this.get(key);
            send('Hooked firestore_DocumentSnapshot_get, key: ' + key + ", return: " + resObj);
            if (keyStr != null && newVal != null && keyStr != undefined && newVal != undefined && key == keyStr) {
                var jvar;
                if (typeof (newVal) == 'boolean') {
                    jvar = Java.use('java.lang.Boolean').$new(newVal);
                }
                if (typeof (newVal) == 'string') {
                    jvar = Java.use('java.lang.String').$new(newVal);
                }
                if (typeof (newVal) == 'number') {
                    jvar = Java.use('java.lang.Integer').$new(newVal);
                }
                if (jvar != null) {
                    var objVal = Java.cast(jvar, Java.use('java.lang.Object'));
                    send('Hooked firestore_DocumentSnapshot_get, override values: key: ' + keyStr + ", return: " + newVal);
                    return objVal;
                }
            }
            return resObj;
        }
    });
}

function hook_firestore_QueryDocumentSnapshot_getData(keyStr, newVal) {
    Java.perform(function () {
        Java.use('com.google.firebase.firestore.QueryDocumentSnapshot').getData.overload().implementation = function () {
            var map = this.getData();
            send('Hooked firestore_QueryDocumentSnapshot_getData, map:');
            if (keyStr !== null && newVal !== null && keyStr !== undefined && newVal !== undefined) {
                UpdateHashMap(map, keyStr, newVal);
            } else {
                printHashMap(map);
            }
            return map;
        }
    });
}

function hook_NetworkCapabilities_hasTransport() {
    Java.perform(function () {
        Java.use('android.net.NetworkCapabilities').hasTransport.overload('int').implementation = function (typeInt) {
            var res = this.hasTransport(typeInt);
            send('Hooked NetworkCapabilities_hasTransport, typeInt: ' + typeInt + ", response: " + res);
            if (typeInt == 4) {
                send('VPN check, return false');
                return false;
            }
            return res;
        }
    });
}

function hook_NetworkInterface_getName() {
    Java.perform(function () {
        Java.use('java.net.NetworkInterface').getName.overload().implementation = function () {
            var res = this.getName();
            send('Hooked NetworkInterface_getName, name: ' + res);
            if (res == 'tun0' || res == 'ppp0') {
                send('Hooked NetworkInterface_getName, return value: dummy0');
                return 'dummy0';
            }
            return res;
        }
    });
}

function hook_ReferrerDetails_getInstallReferrer(newVal) {
    Java.perform(function () {
        var com_android_installreferrer_api_ReferrerDetails = Java.use('com.android.installreferrer.api.ReferrerDetails');
        com_android_installreferrer_api_ReferrerDetails.getInstallReferrer.overload().implementation = function () {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.getInstallReferrer`);
            let result = this['getInstallReferrer']();
            console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getInstallReferrer result=${result}`);
            if (newVal !== null && newVal !== undefined) {
                result = newVal;
                console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getInstallReferrer value to return=${result}`);
            }
            // stackTrace2();
            return result;
        };
    });
}

function hook_ReferrerDetails_getReferrerClickTimestampServerSeconds(newVal) {
    Java.perform(function () {
        var com_android_installreferrer_api_ReferrerDetails = Java.use('com.android.installreferrer.api.ReferrerDetails');
        com_android_installreferrer_api_ReferrerDetails.getReferrerClickTimestampServerSeconds.overload().implementation = function () {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampServerSeconds`);
            let result = this['getReferrerClickTimestampServerSeconds']();
            console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampServerSeconds result=${result}`);
            if (newVal !== null && newVal !== undefined) {
                result = newVal;
                console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampServerSeconds value to return=${result}`);
            }
            return result;
        }
    });
}

function hook_ReferrerDetails_getInstallBeginTimestampServerSeconds(newVal) {
    Java.perform(function () {
        var com_android_installreferrer_api_ReferrerDetails = Java.use('com.android.installreferrer.api.ReferrerDetails');
        com_android_installreferrer_api_ReferrerDetails.getInstallBeginTimestampServerSeconds.overload().implementation = function () {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.getInstallBeginTimestampServerSeconds`);
            let result = this['getInstallBeginTimestampServerSeconds']();
            console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getInstallBeginTimestampServerSeconds result=${result}`);
            if (newVal !== null && newVal !== undefined) {
                result = newVal;
                console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getInstallBeginTimestampServerSeconds value to return=${result}`);
            }
            return result;
        }
    });
}

function hook_ReferrerDetails_getReferrerClickTimestampSeconds(newVal) {
    Java.perform(function () {
        var com_android_installreferrer_api_ReferrerDetails = Java.use('com.android.installreferrer.api.ReferrerDetails');
        com_android_installreferrer_api_ReferrerDetails.getReferrerClickTimestampSeconds.overload().implementation = function () {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampSeconds`);
            let result = this['getReferrerClickTimestampSeconds']();
            console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampSeconds result=${result}`);
            if (newVal !== null && newVal !== undefined) {
                result = newVal;
                console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampSeconds value to return=${result}`);
            }
            return result;
        }
    });
}

function hook_ReferrerDetails_getInstallBeginTimestampSeconds(newVal) {
    Java.perform(function () {
        let com_android_installreferrer_api_ReferrerDetails = Java.use('com.android.installreferrer.api.ReferrerDetails');
        com_android_installreferrer_api_ReferrerDetails.getInstallBeginTimestampSeconds.overload().implementation = function () {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.getInstallBeginTimestampSeconds`);
            let result = this['getInstallBeginTimestampSeconds']();
            console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getInstallBeginTimestampSeconds result=${result}`);
            if (newVal !== null && newVal !== undefined) {
                result = newVal;
                console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampSeconds value to return=${result}`);
            }
            return result;
        }
    });
}

function hook_BatteryManager_getIntProperty(value) {
    Java.perform(function () {
        let batteryManager = Java.use('android.os.BatteryManager');
        batteryManager.getIntProperty.overload('int').implementation = function (propId) {
            let result = this['getIntProperty'](propId);
            send("[+] Hooked BatteryManager_getIntProperty, property int: " + propId + ", result: " + result);
            let fakePercentage = value;
            send("[+] Hooked BatteryManager_getIntProperty, fake percentage: " + fakePercentage);
            if (result > 90) {
                return fakePercentage;
            }
            return result;
        };
    });
}

function hook_StringBuilder_append() {
    Java.perform(function () {
        var strBldCls = Java.use('java.lang.StringBuilder');

        strBldCls.append.overloads.forEach(function (overload, index) {
            // Check if the overload takes 'java.lang.String' as the only argument
            if (overload.argumentTypes.length === 1 && overload.argumentTypes[0].className === 'java.lang.String') {
                console.log("[+] Hooking Overload " + index + ": StringBuilder.append(String)");

                overload.implementation = function (str) {
                    // Call the original implementation
                    let result = this.append(str);
                    // Example logic: Check for specific string pattern
                    if (str.endsWith('/su') || str === "\n") {
                        console.log("[*#*] Overload " + index + ": StringBuilder.append(String) called with: " + str);
                        var emptyStrBld = strBldCls.$new("");
                        console.log("[*#*] sizeof empty strBld " + emptyStrBld.length());
                        return emptyStrBld; // Return a new empty StringBuilder
                    }
                    return result; // Return the original result
                };
            }
        });
    });
}

function hook_StringBuilder_length() {
    Java.perform(function () {
        var StringBuilder = Java.use('java.lang.StringBuilder');

        // Hook the `length()` method
        StringBuilder.length.overloads.forEach(function (overload, index) {
            console.log("[*] Hooking StringBuilder.length overload " + index);

            overload.implementation = function () {
                // Log when the method is called

                // Call the original implementation
                var result = overload.apply(this, arguments);

                if (this.toString().indexOf('/su') != -1) {
                    console.log("[*#*] StringBuilder value: " + this.toString());
                    console.log("[*#*] StringBuilder return length 0");
                    result = 0;
                }

                return result; // Return the original length
            };
        });
    });

}

function wifiNetwork_hook() {
    Java.perform(function () {

        // Network override

        var classx = Java.use("android.net.ConnectivityManager");
        var networkInfo = classx.getActiveNetworkInfo;
        networkInfo.implementation = function (args) {
            console.log('[!] Hook getActiveNetworkInfo()');
            var netInfo = networkInfo.call(this);
            // console.log('\t[!] netInfo1: ' + netInfo);
            // when use SIM
            // [!] returnVal:[type: MOBILE[LTE], state: CONNECTED/CONNECTED, reason: (unspecified), extra: internet, failover: false, available: true, roaming: false]
            // return  networkInfo.call(this);

            var networkInfo_class = Java.use("android.net.NetworkInfo");
            // var networkInfo2 = networkInfo2.$new(1, 0, "WIFI", "subWifi");
            var networkInfo2 = networkInfo_class.$new(0, 0, "MOBILE", "LTE");
            var netDetailedState = Java.use("android.net.NetworkInfo$DetailedState");
            networkInfo2.mIsAvailable.value = true;
            networkInfo2.setDetailedState(netDetailedState.CONNECTED.value, null, null);
            console.log('\t[!] return modified networkInfo');
            // console.log('\t[!] netInfo2: ' + networkInfo2);
            return networkInfo2;
        };

        var classx = Java.use("android.net.NetworkCapabilities");
        var hasTransport = classx.hasTransport;
        hasTransport.implementation = function (args) {
            console.log('[!] Hook NetworkCapabilities.hasTransport(i)');
            console.log("\t[!] Hook hasTransport(" + args + ")");
            var oldResult = hasTransport.call(this, args);
            console.log("\t[!] oldResult: " + oldResult);
            if (args == 0) {
                var newResult = true;
                console.log("\t[!] newResult: " + newResult);
                return newResult;
            } else {
                return false;
            }
            return false;
        };
    });
}

/**
 * Sets up Frida hooks to spoof specific Android system properties.
 */
function setupSystemPropertyHooks() {

    const spoofedSettings = {
        "adb_enabled": "0",
        "development_settings_enabled": "0",
        "android_id": generateRandomAndroidId(),
        "auto_time": "1",
        "auto_time_zone": "1",
        "debug_app": null,
        "http_proxy": "0",
        "install_non_market_apps": "0",
        "bluetooth_name": "samsung",
        "wifi": "1",
        "wait_for_debugger": "0",
        "stay_on_while_plugged_in": "0",
        "wifi_on": "1",
        "mobile_data": "1",
    };

    const NameValueCache = Java.use("android.provider.Settings$NameValueCache");

    NameValueCache.getStringForUser.implementation = function (...args) {
        const settingName = args[1];
        let result;

        if (Object.prototype.hasOwnProperty.call(spoofedSettings, settingName)) {
            result = spoofedSettings[settingName];
        } else {
            result = this.getStringForUser(...args);
        }

        const logInfo = {
            caller: "Setting",
            className: "android.provider.Settings",
            methodName: "getStringForUser",
            returnValue: result,
            arguments: settingName,
        };

        console.log(JSON.stringify(logInfo));

        return result;
    };
}

function NameValueTable_getStringForUser() //// same as - setupSystemPropertyHooks
{
    var NameValueCache = Java.use("android.provider.Settings$NameValueCache");
    var signature = NameValueCache.getStringForUser.overloads[0].toString()
    var setting_key_name = {
        "adb_enabled": "0",
        "development_settings_enabled": "0",
        "android_id": generateRandomAndroidId(),
        "auto_time": "1",
        "auto_time_zone": "1",
        "debug_app": null,
        //"http_proxy": null,
        "install_non_market_apps": "0",
        "http_proxy": "0",
        "bluetooth_name": "samsung",
        "wifi": "1",
        "wait_for_debugger": "0",
        "stay_on_while_plugged_in": "0",
        "wifi_on": "1",
        "mobile_data": "1",
    }

    NameValueCache.getStringForUser.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        var keyName = args[1];
        let printStackFlag = false;

        if (keyName in setting_key_name) {
            var result = setting_key_name[keyName];
            if (keyName.indexOf("adb_enabled") != -1 || keyName.indexOf("development_settings_enabled") != -1) {
                printStackFlag = true;
            }
        }
        else {
            var result = this.getStringForUser.apply(this, args)
        }
        if (result == null)
            return result
        var info = {
            caller: "Setting",
            className: "android.provider.Settings",
            methodName: "getStringForUser",
            returnValue: result,
            arguments: keyName,
            signature: signature

        }

        send(info);
        if (printStackFlag) {
            stackTrace2();
        }

        return result

    }
}

function hookReactBridge() {
    var CatalystInstanceImpl = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');

    // Hooking the overload with 'PendingJSCall' parameter
    CatalystInstanceImpl.callFunction.overload('com.facebook.react.bridge.CatalystInstanceImpl$PendingJSCall').implementation = function (pendingJSCall) {
        console.log('[Hook] callFunction(PendingJSCall) called');
        console.log('PendingJSCall: ' + pendingJSCall);
        return this.callFunction(pendingJSCall);
    };

    // Hooking the overload with 'String, String, NativeArray' parameters
    CatalystInstanceImpl.callFunction.overload('java.lang.String', 'java.lang.String', 'com.facebook.react.bridge.NativeArray').implementation = function (module, method, args) {
        console.log('[Hook] callFunction(String, String, NativeArray) called');
        console.log('Module: ' + module);
        console.log('Method: ' + method);
        console.log('args: ' + args);
        return this.callFunction(module, method, args);
    };
}

function findClassInLoader(className) {
    var classFactory;
    var clzName = className;

    var classLoaders = Java.enumerateClassLoadersSync();
    for (var classLoader in classLoaders) {
        try {
            classLoaders[classLoader].findClass(clzName);
            classFactory = Java.ClassFactory.get(classLoaders[classLoader]);
            console.log('classLoader number: ' + classLoader + ', classLoader name: ' + classLoaders[classLoader]);
            break;
        } catch (e) {
            // console.log( e);*
            continue;
        }
    }

    var clz = classFactory.use(clzName);
    return clz
}

function pairip_license_bypass() {
    Java.perform(function () {
        try {
            let ResponseValidator = Java.use('com.pairip.licensecheck.ResponseValidator');
            ResponseValidator.validateResponse.overload("android.os.Bundle", "java.lang.String").implementation = function (arg0, arg1) {
                console.log(`[->] validateResponse: arg0=${arg0}, arg1=${arg1}`);
                console.log("Bypassing validateResponse by returning immideately...");
                return
            };

            let LicenseClient = Java.use('com.pairip.licensecheck.LicenseClient');
            LicenseClient.processResponse.overload("int", "android.os.Bundle").implementation = function (arg0, arg1) {
                console.log(`[->] processResponse: arg0=${arg0}, arg1=${arg1}`);
                console.log(`Bypassing processResponse by changing [arg0] from ${arg0} to 0`);
                this['processResponse'](0, arg1);
            };
        }
        catch { }
    });
}

function hook_jsonObj_writeTo(match) {
    var jsonObjCls = Java.use("org.json.JSONObject");

    jsonObjCls.writeTo.implementation = function (jsonStringer) {
        if (!jsonStringer) return this.writeTo(jsonStringer);

        var jsonStr = jsonStringer.toString();
        if (jsonStr && (!match || jsonStr.includes(match))) {
            console.log("Json: " + jsonStr);
            stackTrace2();
        }

        return this.writeTo(jsonStringer);
    };
}

function hook_ClipboardManager_getPrimaryClip() {
    Java.perform(function () {
        Java.use('android.content.ClipboardManager').getPrimaryClip.overload().implementation = function () {
            var clipVal = this.getPrimaryClip();
            send('Hooked fandroid.content.ClipboardManager.getPrimaryClip, value: ' + clipVal);
            stackTrace2();
            return clipVal;
        }
    });
}

function bypass_installReferrer() {
    try {
        let com_android_installreferrer_api_ReferrerDetails = Java.use("com.android.installreferrer.api.ReferrerDetails");
        com_android_installreferrer_api_ReferrerDetails.$init.overload("android.os.Bundle").implementation = function (arg0) {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.<init>: arg0=${arg0}`);
            this["$init"](arg0);
            let installReferrer = "utm_source=facebook&utm_medium=social"; // This is the important part.

            let time = new Date().getTime() / 1000;
            let installBeginTimestampSeconds = time - 30;
            let installBeginTimestampServerSeconds = time - 31;
            let referrerClickTimestampSeconds = time - 60;
            let referrerClickTimestampServerSeconds = time - 59;

            this.mOriginalBundle.value.putString("install_referrer", installReferrer);
            this.mOriginalBundle.value.putString("install_version", "1.0");
            this.mOriginalBundle.value.putLong("install_begin_timestamp_seconds", installBeginTimestampSeconds);
            this.mOriginalBundle.value.putLong("install_begin_timestamp_server_seconds", installBeginTimestampServerSeconds);
            this.mOriginalBundle.value.putLong("referrer_click_timestamp_seconds", referrerClickTimestampSeconds);
            this.mOriginalBundle.value.putLong("referrer_click_timestamp_server_seconds", referrerClickTimestampServerSeconds);
        };
    }
    catch { }
}


function HookSyncAdapter() {
    hook_account_init();
    hook_AccountManager_addAccountExplicitly();
    hook_ContentResolver_isSyncPending();
    hook_ContentResolver_requestSync();
    hook_ContentResolver_addPeriodicSync();
}

function hookURL(match) {
    if (match == null || match !== undefined) {
        match = 'zzzz';
    }

    hook_webview_loadUrl(match);
    hook_webview_loadUrl_2(match);
    hook_URL_openConnection(match);
    hook_URL_new(match);
}

function hookCipher() {
    hook_encryption_doFinal();
    hook_encryption_cipher();
    hook_encryption_aes();
}

function webViewHooks() {
    hook_webSettings_setJavaScriptEnabled();
    hook_webview_evaluateJavascript();
    hook_webview_addJavascriptInterface();
    hook_WebChromeClient_shouldOverrideUrlLoading();
    hook_webSettings_getUserAgentString();
}

function bypassKeyboardTimezone(locale, timezone) {
    hook_InputMethodSubtype_getLanguageTag(locale);
    hook_TimeZone_getDefault(timezone);
    hook_TimeZone2_getDefault(timezone);
}

function spoofLocale(newLanguageCode, newCountryCode) {
    const Application = Java.use('android.app.Application');
    const Locale = Java.use('java.util.Locale');

    Application.attachBaseContext.implementation = function (context) {
        console.log("Intercepting Application.attachBaseContext to change locale.");

        const resources = context.getResources();
        const config = resources.getConfiguration();
        const newLocale = Locale.forLanguageTag(newLanguageCode + "-" + newCountryCode);
        config.setLocale(newLocale);

        const newContext = context.createConfigurationContext(config);
        this.attachBaseContext(newContext);
        console.log("Locale successfully spoofed to: " + newLocale.toString());
    };

    Locale.getCountry.implementation = function () {
        //console.log(`[Locale] Intercepted getCountry(), returning '${newCountryCode}'.`);
        return newCountryCode;
    };

    Locale.getLanguage.implementation = function () {
        //console.log(`[Locale] Intercepted getLanguage(), returning '${newLanguageCode}'.`);
        return newLanguageCode;
    };

    Locale.toLanguageTag.implementation = function () {
        const newLanguageTag = `${newLanguageCode}-${newCountryCode}`;
        //console.log(`[Locale] Intercepted toLanguageTag(), returning '${newLanguageTag}'.`);
        return newLanguageTag;
    };
}

function spoofTimezone(timezoneId) {
    const TimeZone = Java.use('java.util.TimeZone');

    TimeZone.getDefault.implementation = function () {
        console.log(`[Timezone] Spoofing TimeZone.getDefault() to '${timezoneId}'.`);
        return TimeZone.getTimeZone(timezoneId);
    };

    TimeZone.getID.implementation = function () {
        const originalId = this.getID.call(this);
        console.log(`[Timezone] Intercepted getID() on '${originalId}'. Spoofing to '${timezoneId}'.`);
        return timezoneId;
    };
}

function spoofSimInfo(countryIso, operatorCode, operatorName, mcc, mnc) {
    // Get a wrapper for the Resources class
    const Resources = Java.use('android.content.res.Resources');

    // Hook the getConfiguration() method
    Resources.getConfiguration.implementation = function () {
        // Call the original method to get the real Configuration object
        const config = this.getConfiguration();

        // Modify the mcc and mnc fields directly on the Configuration object
        config.mcc.value = mcc;
        config.mnc.value = mnc;

        // Return the modified object
        return config;
    };

    // Hook TelephonyManager
    const TelephonyManager = Java.use('android.telephony.TelephonyManager');

    TelephonyManager.getSimCountryIso.overload().implementation = function () {
        console.log(`[SIM] Spoofing getSimCountryIso() with: ${countryIso}`);
        return countryIso;
    };
    TelephonyManager.getSimCountryIso.overload('int').implementation = function (slotIndex) {
        console.log(`[SIM] Spoofing getSimCountryIso(slot: ${slotIndex}) with: ${countryIso}`);
        return countryIso;
    };

    TelephonyManager.getNetworkCountryIso.overload().implementation = function () {
        console.log(`[SIM] Spoofing getNetworkCountryIso() with: ${countryIso}`);
        return countryIso;
    };
    TelephonyManager.getNetworkCountryIso.overload('int').implementation = function (subId) {
        console.log(`[SIM] Spoofing getNetworkCountryIso(subId: ${subId}) with: ${countryIso}`);
        return countryIso;
    };

    TelephonyManager.getSimOperator.overload().implementation = function () {
        console.log(`[SIM] Spoofing getSimOperator() with: ${operatorCode}`);
        return operatorCode.toString();
    };
    TelephonyManager.getSimOperator.overload('int').implementation = function (subId) {
        console.log(`[SIM] Spoofing getSimOperator(subId: ${subId}) with: ${operatorCode}`);
        return operatorCode.toString();
    };

    TelephonyManager.getSimOperatorName.overload().implementation = function () {
        console.log(`[SIM] Spoofing getSimOperatorName() with: ${operatorName}`);
        return operatorName;
    };
    TelephonyManager.getSimOperatorName.overload('int').implementation = function (subId) {
        console.log(`[SIM] Spoofing getSimOperatorName(subId: ${subId}) with: ${operatorName}`);
        return operatorName;
    };

    TelephonyManager.getNetworkOperator.overload().implementation = function () {
        console.log(`[SIM] Spoofing getNetworkOperator() with: ${operatorCode}`);
        return operatorCode.toString();
    };
    TelephonyManager.getNetworkOperator.overload('int').implementation = function () {
        console.log(`[SIM] Spoofing getNetworkOperator() with: ${operatorCode}`);
        return operatorCode.toString();
    };
}

function cellularHooksTest(mShortCountryName, mMccMnc, operatorName) {
    var isStackTrace = false;
    var isTrace = false;
    hook_telephonyManager_getSimState(isTrace);
    hook_telephonyManager_isNetworkRoaming(isTrace);

    hook_telephonyManager_getSimCountryIso(mShortCountryName, isStackTrace);
    hook_telephonyManager_getSimOperator(mMccMnc, isStackTrace);
    hook_telephonyManager_getNwOperator(mMccMnc, isStackTrace);
    hook_telephonyManager_getNetworkCountryIso1(mShortCountryName, isStackTrace);
    hook_telephonyManager_getNetworkCountryIso2(mShortCountryName, isStackTrace);

    hook_TelephonyManager_getSubsriberID1(isStackTrace);
    hook_TelephonyManager_getSubsriberID2(isStackTrace);
    hook_TelephonyManager_getDeviceId1(isStackTrace);
    hook_TelephonyManager_getDeviceId2(isStackTrace);

    hook_telephonyManager_getSimOperatorName(operatorName, isStackTrace);
    hook_telephonyManager_getNetworkOperatorName(operatorName, isStackTrace);
}

// --- Main function to hook all properties at once ---
function hookLocation(MockLocationData) {
    const TAG = "[LocationApiHooks]";

    const MockPreferences = {
        getUseAccuracy: function () { return true; },
        getUseAltitude: function () { return true; },
        getUseVerticalAccuracy: function () { return true; },
        getUseSpeed: function () { return true; },
        getUseSpeedAccuracy: function () { return true; },
        getUseMeanSeaLevel: function () { return true; },
        getUseMeanSeaLevelAccuracy: function () { return true; }
    };


    try {
        const Location = Java.use("android.location.Location");

        // Define the methods to hook on the Location class
        const methodsToHook = [
            "getLatitude",
            "getLongitude",
            "getAccuracy",
            "getAltitude",
            "getVerticalAccuracyMeters",
            "getSpeed",
            "getSpeedAccuracyMetersPerSecond"
        ];

        // Conditionally add API-level specific methods
        if (Java.androidVersion >= 31) {
            methodsToHook.push("getMslAltitudeMeters", "getMslAltitudeAccuracyMeters");
        } else {
            console.log(TAG + " getMslAltitudeMeters() and getMslAltitudeAccuracyMeters() not available on this API level");
        }

        methodsToHook.forEach(function (methodName) {
            const method = Location[methodName].overload();
            method.implementation = function () {
                const originalResult = method.call(this);
                console.log(TAG + " Leaving method " + methodName + "()");
                console.log("\t Original result: " + originalResult);

                let modifiedResult = originalResult;

                switch (methodName) {
                    case "getLatitude":
                        modifiedResult = MockLocationData.latitude;
                        break;
                    case "getLongitude":
                        modifiedResult = MockLocationData.longitude;
                        break;
                    case "getAccuracy":
                        if (MockPreferences.getUseAccuracy()) {
                            modifiedResult = MockLocationData.accuracy;
                        }
                        break;
                    case "getAltitude":
                        if (MockPreferences.getUseAltitude()) {
                            modifiedResult = MockLocationData.altitude;
                        }
                        break;
                    case "getVerticalAccuracyMeters":
                        if (MockPreferences.getUseVerticalAccuracy()) {
                            modifiedResult = MockLocationData.verticalAccuracy;
                        }
                        break;
                    case "getSpeed":
                        if (MockPreferences.getUseSpeed()) {
                            modifiedResult = MockLocationData.speed;
                        }
                        break;
                    case "getSpeedAccuracyMetersPerSecond":
                        if (MockPreferences.getUseSpeedAccuracy()) {
                            modifiedResult = MockLocationData.speedAccuracy;
                        }
                        break;
                    case "getMslAltitudeMeters":
                        if (MockPreferences.getUseMeanSeaLevel()) {
                            modifiedResult = MockLocationData.meanSeaLevel;
                        }
                        break;
                    case "getMslAltitudeAccuracyMeters":
                        if (MockPreferences.getUseMeanSeaLevelAccuracy()) {
                            modifiedResult = MockLocationData.meanSeaLevelAccuracy;
                        }
                        break;
                }

                console.log("\t Modified to: " + modifiedResult);
                return modifiedResult;
            };
        });
    } catch (e) {
        console.log(TAG + " Error hooking Location class - " + e.message);
    }
}

function hookLocationManager(MockLocationData) {
    const TAG = "[LocationApiHooks]";
    try {
        const LocationManager = Java.use("android.location.LocationManager");
        const Location = Java.use("android.location.Location");

        LocationManager.getLastKnownLocation.overload('java.lang.String').implementation = function (provider) {
            console.log(TAG + " Leaving method getLastKnownLocation(provider)");
            const originalLocation = this.getLastKnownLocation(provider);
            console.log("\t Original location: " + originalLocation);
            console.log("\t Requested data from: " + provider);

            const fakeLocation = Location.$new(provider);
            fakeLocation.setLatitude(MockLocationData.latitude);
            fakeLocation.setLongitude(MockLocationData.longitude);
            // Additional properties could be set here based on the original Kotlin code.

            console.log("\t Modified location: " + fakeLocation);
            return fakeLocation;
        };
    } catch (e) {
        console.log(TAG + " Error hooking LocationManager - " + e.message);
    }
}


function spoofKeyboardLanguage(localeString, languageTag) {
    const InputMethodSubtype = Java.use('android.view.inputmethod.InputMethodSubtype');

    // Hook getLocale() which returns a string like "en_US"
    InputMethodSubtype.getLocale.implementation = function () {
        const originalLocale = this.getLocale();
        console.log(`[Keyboard] Intercepted getLocale(). Original: ${originalLocale}, Spoofing to: ${localeString}`);
        return localeString;
    };

    // Hook getLanguageTag() which returns a BCP 47 tag like "en-US"
    InputMethodSubtype.getLanguageTag.implementation = function () {
        const originalTag = this.getLanguageTag();
        console.log(`[Keyboard] Intercepted getLanguageTag(). Original: ${originalTag}, Spoofing to: ${languageTag}`);
        return languageTag;
    };
}


function fileDeletionHook() {
    const File = Java.use('java.io.File');

    File.delete.implementation = function () {
        // Get the file path from the File object instance
        const filePath = this.getAbsolutePath();

        // Log the attempt
        console.log(`[JAVA] Intercepted attempt to delete file: ${filePath}`);
        console.log(`[JAVA] ---> Blocked deletion!`);

        // Deceive the app by returning 'true' (success)
        return true;
    };


    // 2. Hooking the Native Layer: unlink() from libc.so
    try {
        const unlinkPtr = Module.findExportByName('libc.so', 'unlink');

        if (unlinkPtr) {
            Interceptor.replace(unlinkPtr, new NativeCallback((pathPtr) => {
                const path = pathPtr.readUtf8String();

                // Log the attempt
                console.log(`[NATIVE] Intercepted attempt to unlink file: ${path}`);
                console.log(`[NATIVE] ---> Blocked deletion!`);

                // Deceive the app by returning 0 (success)
                return 0;
            }, 'int', ['pointer']));
        } else {
            console.log("[NATIVE] Could not find 'unlink' export. It might not be used by this app.");
        }
    } catch (error) {
        console.error("[NATIVE] Error while trying to hook unlink:", error.message);
    }
}


// Helper function to add color to text
function colorize(text, colorCode) {
    return `\x1b[${colorCode}m${text}\x1b[0m`;
}

// Predefined color codes
const COLORS = {
    red: 31,
    green: 32,
    yellow: 33,
    blue: 34,
    magenta: 35,
    cyan: 36,
    white: 37,
    bold: 1,
    brightBlack: 90,
    brightRed: 91,
    brightGreen: 92,
    brightYellow: 93,
    brightBlue: 94,
    brightMagenta: 95,
    brightCyan: 96,
    brightWhite: 97,
};

var dumpCounter = 1;


function dex_loading_tracer() {

    const JavaFile = Java.use("java.io.File");
    const ActivityThread = Java.use('android.app.ActivityThread');
    const FridaFile = File;

    const DexClassLoader = Java.use("dalvik.system.DexClassLoader");

    // DexClassLoader Constructor:
    try {
        DexClassLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            console.log(colorize("[*] DexClassLoader($init) called", COLORS.yellow));
            console.log(colorize("    -> dexPath: " + dexPath, COLORS.yellow));
            console.log(colorize("    -> optimizedDirectory: " + optimizedDirectory, COLORS.yellow));
            console.log(colorize("    -> librarySearchPath: " + librarySearchPath, COLORS.yellow));
            console.log(colorize("    -> parent: " + parent, COLORS.yellow));
            // hookDexClassLoaderMethods()
            dumpDexFromPath(dexPath);
            dumpCounter++
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
    } catch (e) {
        console.log("[-] Could not hook DexClassLoader.init: " + e);
    }

    function hookDexClassLoaderMethods() {
        // findclass():
        try {
            DexClassLoader.findClass.overload("java.lang.String").implementation = function (className) {
                console.log(colorize("[+] DexClassLoader -> findClass: " + className, COLORS.magenta));
                // stackTrace()
                return this.findClass(className);
            };
        } catch (e) {
            console.log("[-] Could not hook DexClassLoader.findClass: " + e);
        }

        // loadClass():
        try {
            DexClassLoader.loadClass.overload('java.lang.String').implementation = function (className) {
                console.log(colorize('[*] DexClassLoader.loadClass called', COLORS.cyan));
                console.log(colorize('    -> Class name: ' + className, COLORS.cyan));
                let loadedClass = this.loadClass(className);
                console.log(colorize('    -> Loaded j.l.Class: ' + loadedClass, COLORS.cyan));
                return loadedClass;
            };
        } catch (e) {
            console.log("[-] Could not hook DexClassLoader.loadClass: " + e);
        }

        // loadClass() overload:
        try {
            DexClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = function (className, resolve) {
                console.log(colorize('[*] DexClassLoader.loadClass [2] called', COLORS.cyan));
                console.log(colorize('    -> Class name: ' + className, COLORS.cyan));
                let loadedClass = this.loadClass(className, resolve);
                console.log(colorize('    -> Loaded class: ' + loadedClass, COLORS.cyan));
                return loadedClass;
            };
        } catch (e) {
            console.log("[-] Could not hook DexClassLoader.loadClass: " + e);
        }
    }

    const BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
    //  BaseDexClassLoader Constructor:
    try {
        BaseDexClassLoader.$init.overload("java.lang.String", "java.io.File", "java.lang.String", "java.lang.ClassLoader").implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            console.log(colorize("[*] BaseDexClassLoader($init) called", COLORS.yellow));
            console.log(colorize("    -> dexPath: " + dexPath, COLORS.yellow));
            console.log(colorize("    -> optimizedDirectory: " + optimizedDirectory, COLORS.yellow));
            console.log(colorize("    -> librarySearchPath: " + librarySearchPath, COLORS.yellow));
            console.log(colorize("    -> parent: " + parent, COLORS.yellow));
            // hookBaseDexClassLoaderMethods()
            dumpDexFromPath(dexPath);
            dumpCounter++
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
    } catch (e) {
        console.log("[-] Could not hook BaseDexClassLoader.init: " + e);
    }

    function hookBaseDexClassLoaderMethods() {
        // findclass():
        try {
            BaseDexClassLoader.findClass.overload("java.lang.String").implementation = function (className) {
                console.log(colorize("[+] BaseDexClassLoader -> findClass: " + className, COLORS.magenta));
                return this.findClass(className);
            };
        } catch (e) {
            console.log("[-] Could not hook BaseDexClassLoader.findClass: " + e);
        }

        // loadClass():
        try {
            BaseDexClassLoader.loadClass.overload('java.lang.String').implementation = function (className) {
                console.log(colorize('[*] BaseDexClassLoader.loadClass called', COLORS.cyan));
                console.log(colorize('    -> Class name: ' + className, COLORS.cyan));
                let loadedClass = this.loadClass(className);
                console.log(colorize('    -> Loaded class: ' + loadedClass, COLORS.cyan));
                return loadedClass;
            };
        } catch (e) {
            console.log("[-] Could not hook BaseDexClassLoader.loadClass: " + e);
        }

        // loadClass() overload:
        try {
            BaseDexClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = function (className, resolve) {
                console.log(colorize('[*] BaseDexClassLoader.loadClass [2] called', COLORS.cyan));
                console.log(colorize('    -> Class name: ' + className, COLORS.cyan));
                let loadedClass = this.loadClass(className, resolve);
                console.log(colorize('    -> Loaded class: ' + loadedClass, COLORS.cyan));
                return loadedClass;
            };
        } catch (e) {
            console.log("[-] Could not hook BaseDexClassLoader.loadClass: " + e);
        }
    }

    const PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    //  PathClassLoader Constructor:
    try {
        PathClassLoader.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function (dexPath, parent) {
            console.log(colorize("[*] PathClassLoader($init) called", COLORS.yellow));
            console.log(colorize("    -> dexPath: " + dexPath, COLORS.yellow));
            console.log(colorize("    -> parent: " + parent, COLORS.yellow));
            dumpDexFromPath(dexPath);
            dumpCounter++
            return this.$init(dexPath, parent);
        };
    } catch (e) {
        console.log("[-] Could not hook PathClassLoader.init: " + e);
    }
    //  PathClassLoader Constructor:
    try {
        PathClassLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function (dexPath, librarySearchPath, parent) {
            console.log(colorize("[*] PathClassLoader($init) called", COLORS.yellow));
            console.log(colorize("    -> dexPath: " + dexPath, COLORS.yellow));
            console.log(colorize("    -> librarySearchPath: " + librarySearchPath, COLORS.yellow));
            console.log(colorize("    -> parent: " + parent, COLORS.yellow));
            dumpDexFromPath(dexPath);
            dumpCounter++
            return this.$init(dexPath, librarySearchPath, parent);
        };
    } catch (e) {
        console.log("[-] Could not hook PathClassLoader.init: " + e);
    }

    function dumpDexFromPath(dexPath) {

        const application = ActivityThread.currentApplication();
        if (application === null) {
            console.log(colorize("[-] Cannot dump DEX: application context not yet available.", COLORS.red));
            return;
        }
        const context = application.getApplicationContext();
        const baseDir = context.getFilesDir().getAbsolutePath();
        const dumpDir = JavaFile.$new(`${baseDir}/dump`);

        if (!dumpDir.exists()) {
            dumpDir.mkdirs();
        }

        // Get the original filename from the path to use in the destination
        // const originalFileName = JavaFile.$new(dexPath).getName();
        const destinationPath = `${dumpDir.getAbsolutePath()}/${dumpCounter}`;

        console.log(colorize(`[*] Copying DEX from ${dexPath}`, COLORS.cyan));

        try {
            // --- Read the entire source file into a buffer ---
            const sourceFile = new FridaFile(dexPath, "rb");
            const dexBuffer = sourceFile.readBytes(); // Reads the entire file
            sourceFile.close();

            // --- Write the buffer to the new destination file ---
            const destinationFile = new FridaFile(destinationPath, "wb");
            destinationFile.write(dexBuffer);
            destinationFile.flush();
            destinationFile.close();

            console.log(colorize(`[+] Copied DEX successfully to: ${destinationPath}`, COLORS.brightGreen));
            console.log(colorize(`    -> To retrieve, run: adb pull "${destinationPath}"`, COLORS.white));

        } catch (e) {
            console.log(colorize(`[-] Failed to copy DEX from path: ${e.message}`, COLORS.red));
        }
    }
}


function in_memory_dex_loading_tracer() {
    const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
    const JavaFile = Java.use("java.io.File");
    const ActivityThread = Java.use('android.app.ActivityThread');
    const FridaFile = File; // Alias for Frida's built-in File API

    try {
        InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function (buffer, loader) {

            console.log(colorize("[*] InMemoryDexClassLoader($init) called", COLORS.brightYellow));
            console.log(colorize("    -> byteBuffer: " + buffer, COLORS.yellow));
            console.log(colorize("    -> parentClassLoader: " + loader, COLORS.yellow));

            const path = getDirectory().getAbsolutePath();
            dumpDex(buffer, `${path}/${0}`);
            dumpCounter++;
            return this.$init(buffer, loader);
        };
    } catch (e) {
        console.log(colorize("[-] Could not hook InMemoryDexClassLoader.$init: " + e, COLORS.red));
    }

    try {
        InMemoryDexClassLoader.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader').implementation = function (buffers, loader) {
            console.log(colorize("\n[*] InMemoryDexClassLoader(ByteBuffer[], ...) hooked!", COLORS.brightYellow));

            const path = getDirectory().getAbsolutePath();
            for (let i = 0; i < buffers.length; i++) {
                dumpDex(buffers[i], `${path}/${i}`);
            }
            dumpCounter++;
            return this.$init(buffers, loader);
        };
    } catch (e) { console.log(colorize("[-] Failed to hook InMemoryDexClassLoader (buffer array): " + e, COLORS.red)); }

    try {
        InMemoryDexClassLoader.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.String', 'java.lang.ClassLoader').implementation = function (buffers, librarySearchPath, loader) {
            console.log(colorize("\n[*] InMemoryDexClassLoader(ByteBuffer[], String, ...) hooked!", COLORS.brightYellow));
            console.log(colorize("    -> librarySearchPath: " + librarySearchPath, COLORS.yellow));

            const path = getDirectory().getAbsolutePath();
            for (let i = 0; i < buffers.length; i++) {
                dumpDex(buffers[i], `${path}/${i}`);
            }
            dumpCounter++;
            return this.$init(buffers, librarySearchPath, loader);
        };
    } catch (e) { console.log(colorize("[-] Failed to hook InMemoryDexClassLoader (buffer array with lib path): " + e, COLORS.red)); }

    function getDirectory() {
        const application = ActivityThread.currentApplication();
        if (application === null) {
            console.log(colorize("[-] Cannot dump DEX: application context not yet available.", COLORS.red));
            return;
        }
        const context = application.getApplicationContext();
        const baseDir = context.getFilesDir().getAbsolutePath();
        const dumpDir = JavaFile.$new(`${baseDir}/dump/inmem${dumpCounter}`);

        if (!dumpDir.exists()) {
            dumpDir.mkdirs();
        }
        return dumpDir;
    }

    function dumpDex(byteBuffer, path) {
        byteBuffer.rewind();
        const remaining = byteBuffer.remaining();

        const dexBytes = [];
        for (let i = 0; i < remaining; i++) { dexBytes.push(byteBuffer.get()); }

        const fridaFile = new FridaFile(path, "wb");
        fridaFile.write(dexBytes);
        fridaFile.flush();
        fridaFile.close();

        console.log(colorize(`[+] Dex dumped successfully to ${path}`, COLORS.brightGreen));
        byteBuffer.rewind();
    }
}

function spoofBatteryStatus(level, isCharging, plugged) {
    // Basic validation for the level parameter
    if (level < 0 || level > 100) {
        console.error("[!] Invalid battery level. Please provide a number between 0 and 100.");
        return;
    }

    const Intent = Java.use('android.content.Intent');
    const BatteryManager = Java.use('android.os.BatteryManager');

    // --- Determine Constants from Arguments ---
    const status = isCharging ?
        BatteryManager.BATTERY_STATUS_CHARGING.value :
        BatteryManager.BATTERY_STATUS_DISCHARGING.value;

    // Set a sensible default for battery health
    const health = BatteryManager.BATTERY_HEALTH_GOOD.value;

    console.log(`[*] Applying battery hook: level=${level}%, charging=${isCharging}, plugged=${plugged}`);

    // --- Hook 1: Intent Broadcasts ---
    Intent.getIntExtra.overload('java.lang.String', 'int').implementation = function (name, defaultValue) {
        if (name === "level") return level;
        if (name === "scale") return 100;
        if (name === "status") return status;
        if (name === "plugged") return plugged;
        if (name === "health") return health;
        return this.getIntExtra(name, defaultValue);
    };

    // --- Hook 2: Direct BatteryManager Queries ---
    const b_CAPACITY = BatteryManager.BATTERY_PROPERTY_CAPACITY.value;
    const b_STATUS = BatteryManager.BATTERY_PROPERTY_STATUS.value;

    BatteryManager.getIntProperty.implementation = function (propId) {
        if (propId === b_CAPACITY) return level;
        if (propId === b_STATUS) return status;
        return this.getIntProperty(propId);
    };

    console.log("[*] Comprehensive battery status hooks are now active.");
}


function mainSpoofer(countryCode) {
    const profile = countryProfiles[countryCode];

    if (!profile) {
        console.error(`[!] No profile found for country code: ${countryCode}`);
        console.log(`[*] Available profiles: ${Object.keys(countryProfiles).join(', ')}`);
        return;
    }
    console.log(`[*] Applying spoofing profile for ${profile.operatorName}, ${profile.country}...`);
    spoofLocale(profile.langCode, profile.country);
    spoofTimezone(profile.timezone);
    spoofSimInfo(profile.country, profile.mcc_mnc, profile.operatorName, profile.mcc, profile.mnc);
    cellularHooksTest(profile.langCode, profile.mcc_mnc, profile.operatorName);
    hookLocation(profile.mockLocationData);
    hookLocationManager(profile.mockLocationData);
    bypassKeyboardTimezone(profile.locale.replace("-", "_"), profile.timezone);
    spoofKeyboardLanguage(profile.locale, profile.locale.replace("-", "_"));
}

// Main
Java.perform(function () {
    send("start activating functions");

    // Available Countries:
    // Brazil, United States, India, Turkey, Ukraine, Indonesia, Thailand, UAE, United Kingdom, Saudi Arabia, Austria, Malaysia, Pakistan, Kazakhstan, 
    // Iran, Russia, Japan, China, Nigeria, Bangladesh, Mexico, Philippines, Egypt, Vietnam, Germany, France, Italy, South Korea, Spain, Argentina,
    // Colombia, Iraq, Sudan, Algeria, Canada, Poland, Morocco, Uzbekistan, Peru, Yemen, Venezuela, Nepal, Australia, Sri Lanka, Chile, Ecuador, Cuba,
    // Guatemala, Romania, Netherlands, Zimbabwe, Cambodia, Belgium, Haiti, Jordan, Sweden, Greece, Portugal, Hungary, Honduras, Belarus, Israel, Croatia,
    // Syria, Taiwan, Malawi, Zambia, Chad, Senegal, Benin, Guinea, Rwanda, Burundi, Somalia, Bolivia, Tunisia, Czechia, Dominican Republic, Azerbaijan, 
    // Singapore, Denmark, Finland, New Zealand, Kuwait, Costa Rica, Norway, Ireland, Hong Kong, Switzerland, Angola, Ethiopia, South Africa, Kenya, 
    // Tanzania, Myanmar (Burma), Uganda, Afghanistan, Ghana, Mozambique, Cameroon, Mali, Burkina Faso, Madagascar, Niger, Libya, Panama, Uruguay, 

    mainSpoofer("Brazil");
    pairip_license_bypass();
    bypass_installReferrer();


    anti_root();
    setupSystemPropertyHooks();
    updateBuildInfo(getBuildProfile("samsungS22"));
    spoofBatteryStatus(50, false, 0);
    multipleUnpining();


    // fileDeletionHook();
    // hookCipher();


    // ****** Network hooks *****

    dex_loading_tracer();
    in_memory_dex_loading_tracer();

    wifiNetwork_hook(); //trick an app into thinking it's connected to a mobile network (LTE) even if it's not.
    hook_NetworkCapabilities_hasTransport(); // prevent an app from detecting if a VPN is active
    hook_NetworkInterface_getName(); // hide the presence of a VPN from a running Android application


    setTimeout(function () {
        send("Running delayed methods")
        hook_installTimeUpdate(72);
    }, 10);

    send("Script finished loading");
});
