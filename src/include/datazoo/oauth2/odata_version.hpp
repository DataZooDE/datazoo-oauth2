#pragma once

// The one OData-shaped thing this library carries, isolated deliberately.
//
// HttpRequest has SetODataVersion() / AddODataVersionHeaders(), which came
// across with the extraction and are depended on by the consumer that this
// code was extracted from. The enum they need was originally declared in a
// ~2500-line OData EDM header that also pulls in tinyxml2 -- pulling that
// into a provider-agnostic OAuth2 library would be real scope creep, so the
// enum lives here instead.
//
// Why its OWN header rather than sitting inside http_client.hpp, where it
// started: http_client.hpp does `using namespace duckdb;` at global scope.
// A consumer that needs only the enum -- to avoid defining it twice and
// breaking every translation unit that sees both -- would have to include all
// of that, and dumping the duckdb namespace into the global one EARLIER than
// before silently changes name lookup. It really does: doing exactly that
// made `EnumType` ambiguous between duckdb::EnumType and the consumer's own,
// in a test file neither header had ever been near.
//
// This header includes nothing and declares nothing else. Keep it that way.

namespace erpl_web {

enum class ODataVersion {
	UNKNOWN,
	V2,
	V4
};

} // namespace erpl_web
