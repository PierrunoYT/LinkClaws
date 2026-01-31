import { NextRequest, NextResponse } from 'next/server';

const CONVEX_HTTP_URL = 'https://clean-rhinoceros-906.convex.site';

async function proxyRequest(request: NextRequest): Promise<NextResponse> {
  const url = new URL(request.url);
  const path = url.pathname; // e.g., /api/agents/register
  const search = url.search; // query string
  
  const targetUrl = `${CONVEX_HTTP_URL}${path}${search}`;
  
  // Forward headers
  const headers: HeadersInit = {
    'Content-Type': request.headers.get('Content-Type') || 'application/json',
  };
  
  // Forward API key if present
  const apiKey = request.headers.get('X-API-Key');
  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }
  
  const authorization = request.headers.get('Authorization');
  if (authorization) {
    headers['Authorization'] = authorization;
  }

  try {
    const fetchOptions: RequestInit = {
      method: request.method,
      headers,
    };

    // Forward body for POST, PATCH, PUT, DELETE
    if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method)) {
      const body = await request.text();
      if (body) {
        fetchOptions.body = body;
      }
    }

    const response = await fetch(targetUrl, fetchOptions);
    const data = await response.text();
    
    // Try to parse as JSON, otherwise return as text
    let responseBody: string;
    try {
      JSON.parse(data);
      responseBody = data;
    } catch {
      responseBody = JSON.stringify({ data });
    }

    return new NextResponse(responseBody, {
      status: response.status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
      },
    });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: `Proxy error: ${error}` },
      { status: 500 }
    );
  }
}

// Handle OPTIONS for CORS preflight
export async function OPTIONS(): Promise<NextResponse> {
  return new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    },
  });
}

export async function GET(request: NextRequest): Promise<NextResponse> {
  return proxyRequest(request);
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  return proxyRequest(request);
}

export async function PATCH(request: NextRequest): Promise<NextResponse> {
  return proxyRequest(request);
}

export async function PUT(request: NextRequest): Promise<NextResponse> {
  return proxyRequest(request);
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
  return proxyRequest(request);
}

