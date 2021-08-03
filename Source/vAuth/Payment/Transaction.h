#pragma once
#include <vector>
#include <string>
class Transaction
{
public:

	std::string id;
	std::string date;
	std::string amount;

	std::vector<string> data;
};