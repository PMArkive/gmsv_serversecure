#include "netfilter/clientmanager.hpp"
#include "netfilter/client.hpp"

#include <stdexcept>
#include <string>
#include <functional>
#include <iostream>
#include <chrono>

using namespace netfilter;

static_assert( ClientManager::MaxClients > 2, "Maximum number of clients should be greater than 2" );
static_assert( ClientManager::MaxQueriesWindow >= 2, "Maximum queries window should be equal or greater than 2" );
static_assert( ClientManager::MaxQueriesPerSecond >= 1, "Maximum queries per second should be equal or greater than 1" );

static void TestWithOptions( const uint32_t client_max_queries_per_sec, const uint32_t max_queries_window, const bool set_global_max_queries_per_sec )
{
	if( client_max_queries_per_sec < 1 )
		throw std::runtime_error( "Maximum queries per second should be equal or greater than 1" );

	if( max_queries_window < 2 )
		throw std::runtime_error( "Maximum queries window should be higher than 2" );

	const uint32_t max_tries_before_ban = client_max_queries_per_sec * max_queries_window - 1;
	constexpr uint32_t beginning_of_times = 0;
	const uint32_t within_window_timeout = max_queries_window - 1;
	const uint32_t outside_window_timeout = max_queries_window + 1;

	ClientManager client_manager;
	client_manager.SetState( true );
	client_manager.SetMaxQueriesPerSecond( client_max_queries_per_sec );
	client_manager.SetMaxQueriesWindow( max_queries_window );

	if( set_global_max_queries_per_sec )
		client_manager.SetGlobalMaxQueriesPerSecond( client_max_queries_per_sec * ClientManager::MaxClients );

	{
		Client client( client_manager, 1 );

		// Check IP rate "max tries - 1" times and confirm it passes
		for( uint32_t tries = 0; tries < max_tries_before_ban; ++tries )
			if( !client.CheckIPRate( beginning_of_times ) )
				throw std::runtime_error( "Client didn't pass IP rate check when it should" );

		// Check IP rate one more time and confirm it doesn't pass
		if( client.CheckIPRate( beginning_of_times ) )
			throw std::runtime_error( "Client passed IP rate check when it shouldn't" );
	}

	// Check IP rate one time for client 1 and confirm it passes both globally and individually
	if( client_manager.CheckIPRate( 1, beginning_of_times ) != ClientManager::RateLimitType::None )
		throw std::runtime_error( "Client 1 didn't pass IP rate check when it should" );

	// Check IP rate one time for clients 2 to max and confirm they pass both globally and individually,
	// if we set the global max queries per second
	// If we don't set that value, we might hit the global limit.
	for( uint32_t address = 2; address <= ClientManager::MaxClients; ++address )
		if( client_manager.CheckIPRate( address, within_window_timeout ) != ClientManager::RateLimitType::None && set_global_max_queries_per_sec )
			throw std::runtime_error( "Client " + std::to_string( address ) + " didn't pass IP rate check when it should" );

	// Check IP rate "max tries - 2" times for all clients and confirm they pass both globally and individually,
	// if we set the global max queries per second
	// If we don't set that value, we might hit the global limit.
	for( uint32_t address = 1; address <= ClientManager::MaxClients; ++address )
		for( uint32_t tries = 0; tries < max_tries_before_ban - 1; ++tries )
			if( client_manager.CheckIPRate( address, within_window_timeout ) != ClientManager::RateLimitType::None && set_global_max_queries_per_sec )
				throw std::runtime_error( "Client " + std::to_string( address ) + " didn't pass IP rate check when it should" );

	// Check IP rate one time for client 1 and confirm it doesn't pass individually
	if( client_manager.CheckIPRate( 1, within_window_timeout ) != ClientManager::RateLimitType::Individual )
		throw std::runtime_error( "Client 1 passed IP rate check when it shouldn't" );

	// Check IP rate one time for client 1 and confirm it passes both globally and individually,
	// since it should have hit the window timeout
	if( client_manager.CheckIPRate( 1, outside_window_timeout ) != ClientManager::RateLimitType::None )
		throw std::runtime_error( "Client 1 didn't pass IP rate check when it should" );

	// Check IP rate one time for client 2 and confirm it doesn't pass individually,
	// since it hasn't hit the window timeout yet (started counting 2 time units ago)
	if( client_manager.CheckIPRate( 2, outside_window_timeout ) == ClientManager::RateLimitType::None )
		throw std::runtime_error( "Client 2 passed IP rate check when it shouldn't" );
}

static void TestPerformance( const uint32_t max_clients_multiplier )
{
	const uint32_t within_window_timeout = ClientManager::MaxQueriesWindow - 1;
	const uint32_t outside_window_timeout = ClientManager::MaxQueriesWindow + 1;

	ClientManager client_manager;
	client_manager.SetState( true );
	client_manager.SetGlobalMaxQueriesPerSecond( ClientManager::MaxClients * ClientManager::MaxQueriesPerSecond * ( ClientManager::MaxQueriesWindow - 1 ) * max_clients_multiplier );

	for( uint32_t time = 0; time < within_window_timeout; ++time )
		for( uint32_t address = 1; address <= ClientManager::MaxClients * max_clients_multiplier; ++address )
			if( client_manager.CheckIPRate( address, time ) != ClientManager::RateLimitType::None )
				throw std::runtime_error( "Client " + std::to_string( address ) + " didn't pass IP rate check at time unit " + std::to_string( time ) + " when it should" );

	for( uint32_t address = 1; address <= ClientManager::MaxClients * max_clients_multiplier; ++address )
		if( client_manager.CheckIPRate( address, outside_window_timeout ) != ClientManager::RateLimitType::None )
			throw std::runtime_error( "Client " + std::to_string( address ) + " didn't pass IP rate check at time unit " + std::to_string( outside_window_timeout ) + " when it should" );
}

inline void Run( const std::string &test_name, std::function<void ( )> test_fn )
{
	const auto start = std::chrono::high_resolution_clock::now( );
	test_fn( );
	const auto end = std::chrono::high_resolution_clock::now( );
	std::cout << "Test '" << test_name << "' took " << std::chrono::duration_cast<std::chrono::milliseconds>( end - start ).count( ) << "ms" << std::endl;
}

int main( int, const char *[] )
{
	Run( "TestWithDefaultOptions", std::bind( TestWithOptions, ClientManager::MaxQueriesPerSecond, ClientManager::MaxQueriesWindow, true ) );
	Run( "TestWithSourceOptions", std::bind( TestWithOptions, 3, 30, true ) );
	Run( "TestWithDefaultOptionsAndNoGlobalMaxQueries", std::bind( TestWithOptions, ClientManager::MaxQueriesPerSecond, ClientManager::MaxQueriesWindow, false ) );
	Run( "TestPerformanceWithClientMultiplier1", std::bind( TestPerformance, 1 ) );
	Run( "TestPerformanceWithClientMultiplier2", std::bind( TestPerformance, 2 ) );
	Run( "TestPerformanceWithClientMultiplier4", std::bind( TestPerformance, 4 ) );
	Run( "TestPerformanceWithClientMultiplier8", std::bind( TestPerformance, 8 ) );
	return 0;
}
