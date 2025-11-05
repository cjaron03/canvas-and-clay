// simple apple touch icon handler to prevent 404 errors
export async function GET() {
	return new Response(null, { status: 204 });
}
