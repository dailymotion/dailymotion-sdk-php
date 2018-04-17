<?php

namespace baorv\dailymotion\exceptions;

class DailymotionAuthException extends DailymotionApiException
{
    public $error = null;
}