#pragma once

/**
 * @brief Defines a base payment processor for handling transactions vs webhooks and other legacy methods
*/
class PaymentProcessor
{
public:

	virtual ~PaymentProcessor() = default;

protected:
	PaymentProcessor() = default;
};